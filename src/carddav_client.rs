//! Minimal `CardDAV` client for Stalwart.
//!
//! The caller's validated Logto bearer is forwarded verbatim on every DAV
//! request. No app password, shared credential, or server-side contact store
//! exists in this service.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::StreamExt as _;
use quick_xml::Reader;
use quick_xml::events::Event;
use reqwest::header::{
    ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MATCH, IF_NONE_MATCH, LOCATION,
};
use reqwest::{Method, StatusCode, Url};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

#[allow(clippy::duration_suboptimal_units)]
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const DISCOVERY_CAP: usize = 256;
const ERROR_SNIPPET_BYTES: usize = 4096;

const CURRENT_USER_PRINCIPAL_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop><d:current-user-principal/></d:prop>
</d:propfind>"#;

const ADDRESSBOOK_HOME_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop><card:addressbook-home-set/></d:prop>
</d:propfind>"#;

const LIST_ADDRESSBOOKS_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/">
  <d:prop>
    <d:resourcetype/>
    <d:displayname/>
    <cs:getctag/>
  </d:prop>
</d:propfind>"#;

const LIST_CONTACTS_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop><d:getetag/><card:address-data/></d:prop>
</card:addressbook-query>"#;

#[derive(Debug, Error)]
pub enum CardDavError {
    #[error("not authenticated to Stalwart CardDAV (token expired or bearer rejected)")]
    Unauthorized,
    #[error("CardDAV resource was not found")]
    NotFound,
    #[error("CardDAV write conflicted with the current ETag")]
    Conflict,
    #[error("CardDAV response exceeds the configured size cap")]
    TooLarge,
    #[error("unsafe or invalid DAV href: {0}")]
    InvalidHref(String),
    #[error("invalid CardDAV data: {0}")]
    InvalidData(String),
    #[error("CardDAV transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("CardDAV endpoint returned non-success status {status}")]
    Upstream { status: u16 },
    #[error("invalid CardDAV XML: {0}")]
    Xml(String),
}

#[derive(Clone, Debug)]
pub struct DavDiscovery {
    pub principal_href: String,
    pub addressbook_home_href: String,
}

#[derive(Clone, Debug)]
pub struct DavAddressBook {
    pub href: String,
    pub display_name: String,
    pub ctag: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DavContact {
    pub href: String,
    pub etag: Option<String>,
    pub vcard: String,
}

#[derive(Clone, Debug)]
pub struct DavWriteResult {
    pub href: String,
    pub etag: Option<String>,
}

#[derive(Clone)]
pub struct CardDavClient {
    http: reqwest::Client,
    base_url: Url,
    discovery_url: Url,
    max_response_bytes: u64,
    discoveries: Arc<RwLock<HashMap<[u8; 32], CachedDiscovery>>>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for CardDavClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardDavClient")
            .field("base_url", &self.base_url)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

#[derive(Clone)]
struct CachedDiscovery {
    discovery: DavDiscovery,
    cached_at: Instant,
}

struct DavHttpResponse {
    status: StatusCode,
    body: Vec<u8>,
    etag: Option<String>,
    location: Option<String>,
}

impl CardDavClient {
    /// Construct a `CardDAV` client rooted at a trusted Stalwart origin.
    /// Returned DAV hrefs are resolved only when they remain on this origin.
    pub fn new(
        stalwart_base: &str,
        connect_ip: Option<&str>,
        max_response_bytes: u64,
    ) -> Result<Self> {
        anyhow::ensure!(max_response_bytes > 0, "CardDAV response cap must be > 0");
        let mut base_url = Url::parse(stalwart_base).context("parse Stalwart DAV base URL")?;
        anyhow::ensure!(
            matches!(base_url.scheme(), "http" | "https") && base_url.host_str().is_some(),
            "Stalwart DAV base URL must be absolute http(s)"
        );
        base_url.set_query(None);
        base_url.set_fragment(None);
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let discovery_url = base_url
            .join(".well-known/carddav")
            .context("build CardDAV discovery URL")?;

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("carddav-mcp/", env!("CARGO_PKG_VERSION")));
        if let Some(ip) = connect_ip {
            let host = base_url
                .host_str()
                .context("Stalwart DAV base URL has no host")?;
            let addr: std::net::IpAddr = ip
                .parse()
                .context("CARDDAV_MCP_STALWART_CONNECT_IP is not a valid IP")?;
            let port = base_url.port_or_known_default().unwrap_or(443);
            builder = builder.resolve(host, std::net::SocketAddr::new(addr, port));
        }
        let http = builder.build().context("build CardDAV HTTP client")?;
        Ok(Self {
            http,
            base_url,
            discovery_url,
            max_response_bytes,
            discoveries: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Discover the caller's principal and address-book home set.
    pub async fn discover(&self, token: &str) -> Result<DavDiscovery, CardDavError> {
        let key = hash_token(token);
        if let Some(discovery) = self.discovery_lookup(&key) {
            return Ok(discovery);
        }

        let principal_response = self
            .propfind(
                token,
                self.discovery_url.clone(),
                "0",
                CURRENT_USER_PRINCIPAL_BODY,
            )
            .await?;
        let responses = parse_multistatus(&principal_response.body)?;
        let principal_href = responses
            .iter()
            .find_map(|r| r.current_user_principal.clone())
            .ok_or_else(|| {
                CardDavError::InvalidData(
                    "discovery response omitted current-user-principal".to_owned(),
                )
            })?;

        let principal_url = self.resolve_href(&principal_href)?;
        let home_response = self
            .propfind(token, principal_url, "0", ADDRESSBOOK_HOME_BODY)
            .await?;
        let responses = parse_multistatus(&home_response.body)?;
        let addressbook_home_href = responses
            .iter()
            .find_map(|r| r.addressbook_home.clone())
            .ok_or_else(|| {
                CardDavError::InvalidData(
                    "principal response omitted addressbook-home-set".to_owned(),
                )
            })?;

        // Resolve once now to reject an off-origin home-set before caching it.
        self.resolve_href(&addressbook_home_href)?;
        let discovery = DavDiscovery {
            principal_href,
            addressbook_home_href,
        };
        self.discovery_insert(key, &discovery);
        Ok(discovery)
    }

    pub async fn list_address_books(
        &self,
        token: &str,
    ) -> Result<Vec<DavAddressBook>, CardDavError> {
        let discovery = self.discover(token).await?;
        let home_url = self.resolve_href(&discovery.addressbook_home_href)?;
        let response = self
            .propfind(token, home_url, "1", LIST_ADDRESSBOOKS_BODY)
            .await?;
        let parsed = parse_multistatus(&response.body)?;
        let home_normalized = normalize_href(&discovery.addressbook_home_href);
        let mut books = Vec::new();
        for item in parsed {
            let Some(href) = item.href else { continue };
            if !item.is_addressbook || normalize_href(&href) == home_normalized {
                continue;
            }
            self.resolve_href(&href)?;
            let display_name = item
                .display_name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| href_tail(&href).unwrap_or_else(|| "Contacts".to_owned()));
            books.push(DavAddressBook {
                href,
                display_name,
                ctag: item.ctag.filter(|ctag| !ctag.is_empty()),
            });
        }
        Ok(books)
    }

    pub async fn list_contacts(
        &self,
        token: &str,
        addressbook_href: &str,
    ) -> Result<Vec<DavContact>, CardDavError> {
        self.query_contacts(token, addressbook_href, LIST_CONTACTS_BODY)
            .await
    }

    pub async fn search_contacts(
        &self,
        token: &str,
        addressbook_href: &str,
        query: &str,
    ) -> Result<Vec<DavContact>, CardDavError> {
        if query.trim().is_empty() {
            return Err(CardDavError::InvalidData(
                "search query must not be empty".to_owned(),
            ));
        }
        if query.len() > 256 || query.chars().any(is_illegal_xml_char) {
            return Err(CardDavError::InvalidData(
                "search query is too long or contains an XML control character".to_owned(),
            ));
        }
        let escaped = escape_xml(query);
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop><d:getetag/><card:address-data/></d:prop>
  <card:filter test="anyof">
    <card:prop-filter name="FN"><card:text-match collation="i;unicode-casemap" match-type="contains">{escaped}</card:text-match></card:prop-filter>
    <card:prop-filter name="N"><card:text-match collation="i;unicode-casemap" match-type="contains">{escaped}</card:text-match></card:prop-filter>
    <card:prop-filter name="EMAIL"><card:text-match collation="i;unicode-casemap" match-type="contains">{escaped}</card:text-match></card:prop-filter>
    <card:prop-filter name="TEL"><card:text-match collation="i;unicode-casemap" match-type="contains">{escaped}</card:text-match></card:prop-filter>
    <card:prop-filter name="ORG"><card:text-match collation="i;unicode-casemap" match-type="contains">{escaped}</card:text-match></card:prop-filter>
  </card:filter>
</card:addressbook-query>"#
        );
        self.query_contacts(token, addressbook_href, &body).await
    }

    async fn query_contacts(
        &self,
        token: &str,
        addressbook_href: &str,
        body: &str,
    ) -> Result<Vec<DavContact>, CardDavError> {
        let url = self.resolve_href(addressbook_href)?;
        let method = Method::from_bytes(b"REPORT")
            .map_err(|e| CardDavError::InvalidData(format!("REPORT method: {e}")))?;
        let response = self
            .send(
                token,
                self.http
                    .request(method, url)
                    .header("Depth", "1")
                    .header(CONTENT_TYPE, "application/xml; charset=utf-8")
                    .header(ACCEPT, "application/xml, text/vcard")
                    .body(body.to_owned()),
            )
            .await?;
        ensure_multistatus(response.status)?;
        let mut contacts = Vec::new();
        for item in parse_multistatus(&response.body)? {
            let (Some(href), Some(vcard)) = (item.href, item.address_data) else {
                continue;
            };
            self.resolve_href(&href)?;
            contacts.push(DavContact {
                href,
                etag: item.etag.filter(|etag| !etag.is_empty()),
                vcard,
            });
        }
        Ok(contacts)
    }

    pub async fn get_contact(
        &self,
        token: &str,
        contact_href: &str,
    ) -> Result<DavContact, CardDavError> {
        let url = self.resolve_href(contact_href)?;
        let response = self
            .send(
                token,
                self.http
                    .get(url)
                    .header(ACCEPT, "text/vcard, text/x-vcard"),
            )
            .await?;
        match response.status {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Err(CardDavError::NotFound),
            status => {
                return Err(CardDavError::Upstream {
                    status: status.as_u16(),
                });
            }
        }
        let vcard = String::from_utf8(response.body)
            .map_err(|e| CardDavError::InvalidData(format!("vCard is not UTF-8: {e}")))?;
        Ok(DavContact {
            href: contact_href.to_owned(),
            etag: response.etag,
            vcard,
        })
    }

    pub async fn create_contact(
        &self,
        token: &str,
        addressbook_href: &str,
        uid: &str,
        vcard: &str,
    ) -> Result<DavWriteResult, CardDavError> {
        let mut url = self.resolve_href(addressbook_href)?;
        let filename = format!("{uid}.vcf");
        url.path_segments_mut()
            .map_err(|()| CardDavError::InvalidHref(addressbook_href.to_owned()))?
            .pop_if_empty()
            .push(&filename);
        url.set_query(None);
        url.set_fragment(None);
        let href = url.path().to_owned();
        let response = self
            .send(
                token,
                self.http
                    .put(url)
                    .header(CONTENT_TYPE, "text/vcard; charset=utf-8")
                    .header(IF_NONE_MATCH, "*")
                    .body(vcard.to_owned()),
            )
            .await?;
        match response.status {
            StatusCode::CREATED | StatusCode::NO_CONTENT | StatusCode::OK => Ok(DavWriteResult {
                href: response.location.unwrap_or(href),
                etag: response.etag,
            }),
            StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT => Err(CardDavError::Conflict),
            status => Err(CardDavError::Upstream {
                status: status.as_u16(),
            }),
        }
    }

    pub async fn update_contact(
        &self,
        token: &str,
        contact_href: &str,
        etag: Option<&str>,
        vcard: &str,
    ) -> Result<DavWriteResult, CardDavError> {
        let url = self.resolve_href(contact_href)?;
        let mut request = self
            .http
            .put(url)
            .header(CONTENT_TYPE, "text/vcard; charset=utf-8")
            .body(vcard.to_owned());
        request = request.header(IF_MATCH, etag.unwrap_or("*"));
        let response = self.send(token, request).await?;
        match response.status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(DavWriteResult {
                href: response.location.unwrap_or_else(|| contact_href.to_owned()),
                etag: response.etag,
            }),
            StatusCode::NOT_FOUND => Err(CardDavError::NotFound),
            StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT => Err(CardDavError::Conflict),
            status => Err(CardDavError::Upstream {
                status: status.as_u16(),
            }),
        }
    }

    pub async fn delete_contact(
        &self,
        token: &str,
        contact_href: &str,
        etag: Option<&str>,
    ) -> Result<(), CardDavError> {
        let url = self.resolve_href(contact_href)?;
        let request = self.http.delete(url).header(IF_MATCH, etag.unwrap_or("*"));
        let response = self.send(token, request).await?;
        match response.status {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => Err(CardDavError::NotFound),
            StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT => Err(CardDavError::Conflict),
            status => Err(CardDavError::Upstream {
                status: status.as_u16(),
            }),
        }
    }

    pub fn evict(&self, token: &str) {
        let key = hash_token(token);
        if let Ok(mut cache) = self.discoveries.write()
            && cache.remove(&key).is_some()
        {
            debug!("evicted CardDAV discovery cache entry");
        }
    }

    async fn propfind(
        &self,
        token: &str,
        url: Url,
        depth: &str,
        body: &str,
    ) -> Result<DavHttpResponse, CardDavError> {
        let method = Method::from_bytes(b"PROPFIND")
            .map_err(|e| CardDavError::InvalidData(format!("PROPFIND method: {e}")))?;
        let response = self
            .send(
                token,
                self.http
                    .request(method, url)
                    .header("Depth", depth)
                    .header(CONTENT_TYPE, "application/xml; charset=utf-8")
                    .header(ACCEPT, "application/xml")
                    .body(body.to_owned()),
            )
            .await?;
        ensure_multistatus(response.status)?;
        Ok(response)
    }

    async fn send(
        &self,
        token: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<DavHttpResponse, CardDavError> {
        let response = request.bearer_auth(token).send().await?;
        let status = response.status();
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            let snippet = read_prefix(response, ERROR_SNIPPET_BYTES).await;
            warn!(
                status = status.as_u16(),
                body = %String::from_utf8_lossy(&snippet),
                "Stalwart CardDAV rejected bearer"
            );
            self.evict(token);
            return Err(CardDavError::Unauthorized);
        }

        let body = read_limited(response, self.max_response_bytes).await?;
        Ok(DavHttpResponse {
            status,
            body,
            etag,
            location,
        })
    }

    fn resolve_href(&self, href: &str) -> Result<Url, CardDavError> {
        if href.trim() != href || href.is_empty() {
            return Err(CardDavError::InvalidHref(href.to_owned()));
        }
        let resolved = self
            .base_url
            .join(href)
            .map_err(|_| CardDavError::InvalidHref(href.to_owned()))?;
        let same_origin = resolved.scheme() == self.base_url.scheme()
            && resolved.host_str() == self.base_url.host_str()
            && resolved.port_or_known_default() == self.base_url.port_or_known_default();
        if !same_origin
            || !resolved.username().is_empty()
            || resolved.password().is_some()
            || resolved.fragment().is_some()
        {
            return Err(CardDavError::InvalidHref(href.to_owned()));
        }
        Ok(resolved)
    }

    fn discovery_lookup(&self, key: &[u8; 32]) -> Option<DavDiscovery> {
        let cache = self.discoveries.read().ok()?;
        cache.get(key).and_then(|entry| {
            (entry.cached_at.elapsed() < DISCOVERY_TTL).then(|| entry.discovery.clone())
        })
    }

    fn discovery_insert(&self, key: [u8; 32], discovery: &DavDiscovery) {
        let Ok(mut cache) = self.discoveries.write() else {
            return;
        };
        if cache.len() >= DISCOVERY_CAP {
            cache.retain(|_, entry| entry.cached_at.elapsed() < DISCOVERY_TTL);
        }
        if cache.len() >= DISCOVERY_CAP
            && !cache.contains_key(&key)
            && let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(key, _)| *key)
        {
            cache.remove(&oldest_key);
        }
        cache.insert(
            key,
            CachedDiscovery {
                discovery: discovery.clone(),
                cached_at: Instant::now(),
            },
        );
    }
}

fn ensure_multistatus(status: StatusCode) -> Result<(), CardDavError> {
    if status == StatusCode::MULTI_STATUS || status == StatusCode::OK {
        Ok(())
    } else if status == StatusCode::NOT_FOUND {
        Err(CardDavError::NotFound)
    } else {
        Err(CardDavError::Upstream {
            status: status.as_u16(),
        })
    }
}

async fn read_limited(
    response: reqwest::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, CardDavError> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > max_bytes)
    {
        return Err(CardDavError::TooLarge);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let next_len = body.len().saturating_add(chunk.len());
        if u64::try_from(next_len).unwrap_or(u64::MAX) > max_bytes {
            return Err(CardDavError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_prefix(response: reqwest::Response, max_bytes: usize) -> Vec<u8> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while body.len() < max_bytes {
        let Some(chunk) = stream.next().await else {
            break;
        };
        let Ok(chunk) = chunk else { break };
        let remaining = max_bytes - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() >= remaining {
            break;
        }
    }
    body
}

#[derive(Default)]
struct ParsedDavResponse {
    href: Option<String>,
    display_name: Option<String>,
    ctag: Option<String>,
    etag: Option<String>,
    address_data: Option<String>,
    current_user_principal: Option<String>,
    addressbook_home: Option<String>,
    is_addressbook: bool,
}

#[derive(Clone, Copy)]
enum Capture {
    Href,
    CurrentPrincipal,
    AddressbookHome,
    DisplayName,
    Ctag,
    Etag,
    AddressData,
}

fn parse_multistatus(xml: &[u8]) -> Result<Vec<ParsedDavResponse>, CardDavError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut current: Option<ParsedDavResponse> = None;
    let mut capture: Option<Capture> = None;
    let mut output = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(event)) => {
                let name = String::from_utf8_lossy(event.local_name().as_ref()).into_owned();
                if name == "response" {
                    current = Some(ParsedDavResponse::default());
                }
                if let Some(item) = current.as_mut() {
                    if name == "addressbook" {
                        item.is_addressbook = true;
                    }
                    capture = match name.as_str() {
                        "href" => match stack.last().map(String::as_str) {
                            Some("current-user-principal") => Some(Capture::CurrentPrincipal),
                            Some("addressbook-home-set") => Some(Capture::AddressbookHome),
                            Some("response") => Some(Capture::Href),
                            _ => capture,
                        },
                        "displayname" => Some(Capture::DisplayName),
                        "getctag" => Some(Capture::Ctag),
                        "getetag" => Some(Capture::Etag),
                        "address-data" => Some(Capture::AddressData),
                        _ => capture,
                    };
                }
                stack.push(name);
            }
            Ok(Event::Empty(event)) => {
                let name = String::from_utf8_lossy(event.local_name().as_ref()).into_owned();
                if name == "addressbook"
                    && let Some(item) = current.as_mut()
                {
                    item.is_addressbook = true;
                }
            }
            Ok(Event::Text(text)) => {
                if let (Some(item), Some(kind)) = (current.as_mut(), capture) {
                    let decoded = text
                        .xml10_content()
                        .map_err(|e| CardDavError::Xml(e.to_string()))?;
                    append_capture(item, kind, decoded.as_ref());
                }
            }
            Ok(Event::CData(text)) => {
                if let (Some(item), Some(kind)) = (current.as_mut(), capture) {
                    let decoded = text
                        .xml10_content()
                        .map_err(|e| CardDavError::Xml(e.to_string()))?;
                    append_capture(item, kind, decoded.as_ref());
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if let (Some(item), Some(kind)) = (current.as_mut(), capture) {
                    append_general_ref(item, kind, &reference)?;
                }
            }
            Ok(Event::End(event)) => {
                let name = String::from_utf8_lossy(event.local_name().as_ref()).into_owned();
                if matches!(
                    name.as_str(),
                    "href" | "displayname" | "getctag" | "getetag" | "address-data"
                ) {
                    capture = None;
                }
                if name == "response"
                    && let Some(mut item) = current.take()
                {
                    trim_parsed_response(&mut item);
                    output.push(item);
                }
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(CardDavError::Xml(error.to_string())),
        }
        buf.clear();
    }
    Ok(output)
}

fn append_general_ref(
    item: &mut ParsedDavResponse,
    kind: Capture,
    reference: &quick_xml::events::BytesRef<'_>,
) -> Result<(), CardDavError> {
    if let Some(character) = reference
        .resolve_char_ref()
        .map_err(|error| CardDavError::Xml(error.to_string()))?
    {
        append_capture(item, kind, &character.to_string());
        return Ok(());
    }
    let decoded = reference
        .decode()
        .map_err(|error| CardDavError::Xml(error.to_string()))?;
    let replacement = quick_xml::escape::resolve_xml_entity(decoded.as_ref())
        .ok_or_else(|| CardDavError::Xml(format!("unsupported XML entity reference: {decoded}")))?;
    append_capture(item, kind, replacement);
    Ok(())
}

fn append_capture(item: &mut ParsedDavResponse, capture: Capture, text: &str) {
    let field = match capture {
        Capture::Href => &mut item.href,
        Capture::CurrentPrincipal => &mut item.current_user_principal,
        Capture::AddressbookHome => &mut item.addressbook_home,
        Capture::DisplayName => &mut item.display_name,
        Capture::Ctag => &mut item.ctag,
        Capture::Etag => &mut item.etag,
        Capture::AddressData => &mut item.address_data,
    };
    field.get_or_insert_with(String::new).push_str(text);
}

fn trim_parsed_response(item: &mut ParsedDavResponse) {
    for value in [
        &mut item.href,
        &mut item.display_name,
        &mut item.ctag,
        &mut item.etag,
        &mut item.current_user_principal,
        &mut item.addressbook_home,
    ]
    .into_iter()
    .flatten()
    {
        *value = value.trim().to_owned();
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn normalize_href(href: &str) -> String {
    href.trim_end_matches('/').to_owned()
}

fn href_tail(href: &str) -> Option<String> {
    href.trim_end_matches('/')
        .rsplit('/')
        .find(|part| !part.is_empty())
        .map(ToOwned::to_owned)
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

const fn is_illegal_xml_char(value: char) -> bool {
    matches!(value, '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parses_discovery_and_addressbook_properties() {
        let xml = br#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/">
  <d:response><d:href>/dav/card/u/</d:href><d:propstat><d:prop>
    <d:current-user-principal><d:href>/principals/u/</d:href></d:current-user-principal>
    <card:addressbook-home-set><d:href>/dav/card/u/</d:href></card:addressbook-home-set>
  </d:prop></d:propstat></d:response>
  <d:response><d:href>/dav/card/u/default/</d:href><d:propstat><d:prop>
    <d:displayname>Personal &amp; Shared</d:displayname>
    <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
    <cs:getctag>42</cs:getctag>
  </d:prop></d:propstat></d:response>
</d:multistatus>"#;
        let parsed = parse_multistatus(xml).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0].current_user_principal.as_deref(),
            Some("/principals/u/")
        );
        assert_eq!(parsed[0].addressbook_home.as_deref(), Some("/dav/card/u/"));
        assert!(parsed[1].is_addressbook);
        assert_eq!(parsed[1].display_name.as_deref(), Some("Personal & Shared"));
    }

    #[test]
    fn parses_vcard_from_multistatus() {
        let xml = br#"<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
<d:response><d:href>/dav/card/u/default/a.vcf</d:href><d:propstat><d:prop>
<d:getetag>&quot;abc&quot;</d:getetag>
<card:address-data>BEGIN:VCARD&#13;&#10;VERSION:4.0&#13;&#10;FN:Alice &amp; Bob&#13;&#10;END:VCARD&#13;&#10;</card:address-data>
</d:prop></d:propstat></d:response></d:multistatus>"#;
        let parsed = parse_multistatus(xml).unwrap();
        assert_eq!(parsed[0].etag.as_deref(), Some("\"abc\""));
        let vcard = parsed[0].address_data.as_deref().unwrap();
        assert!(vcard.contains("FN:Alice & Bob"));
        assert!(vcard.contains("\r\n"));
    }

    #[test]
    fn confines_server_hrefs_to_dav_origin() {
        let client = CardDavClient::new("https://dav.example.test", None, 1024).unwrap();
        assert!(client.resolve_href("/dav/card/u/").is_ok());
        assert!(
            client
                .resolve_href("https://dav.example.test/dav/card/u/")
                .is_ok()
        );
        assert!(
            client
                .resolve_href("https://evil.example/dav/card/u/")
                .is_err()
        );
        assert!(client.resolve_href("//evil.example/dav/card/u/").is_err());
    }

    #[test]
    fn xml_escaping_handles_markup() {
        assert_eq!(escape_xml("A&B <C>"), "A&amp;B &lt;C&gt;");
    }

    #[tokio::test]
    async fn bearer_is_forwarded_through_discovery_and_addressbook_listing() {
        let server = MockServer::start().await;
        Mock::given(method("PROPFIND"))
            .and(path("/.well-known/carddav"))
            .and(header("authorization", "Bearer test-token"))
            .and(header("depth", "0"))
            .respond_with(ResponseTemplate::new(207).set_body_raw(
                r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/card/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>/principals/u/</d:href></d:current-user-principal></d:prop></d:propstat></d:response></d:multistatus>"#,
                "application/xml",
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PROPFIND"))
            .and(path("/principals/u/"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(207).set_body_raw(
                r#"<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:response><d:href>/principals/u/</d:href><d:propstat><d:prop><card:addressbook-home-set><d:href>/dav/card/u/</d:href></card:addressbook-home-set></d:prop></d:propstat></d:response></d:multistatus>"#,
                "application/xml",
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PROPFIND"))
            .and(path("/dav/card/u/"))
            .and(header("authorization", "Bearer test-token"))
            .and(header("depth", "1"))
            .respond_with(ResponseTemplate::new(207).set_body_raw(
                r#"<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:response><d:href>/dav/card/u/default/</d:href><d:propstat><d:prop><d:displayname>Contacts</d:displayname><d:resourcetype><d:collection/><card:addressbook/></d:resourcetype></d:prop></d:propstat></d:response></d:multistatus>"#,
                "application/xml",
            ))
            .expect(1)
            .mount(&server)
            .await;

        let client = CardDavClient::new(&server.uri(), None, 1024 * 1024).unwrap();
        let books = client.list_address_books("test-token").await.unwrap();
        assert_eq!(books.len(), 1);
        assert_eq!(books[0].href, "/dav/card/u/default/");
        assert_eq!(books[0].display_name, "Contacts");
    }

    #[tokio::test]
    async fn create_uses_if_none_match_and_never_basic_auth() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/dav/card/u/default/a%2Fb.vcf"))
            .and(header("authorization", "Bearer test-token"))
            .and(header("if-none-match", "*"))
            .and(body_string_contains("UID:a/b"))
            .respond_with(ResponseTemplate::new(201).insert_header("etag", "\"created\""))
            .expect(1)
            .mount(&server)
            .await;
        let client = CardDavClient::new(&server.uri(), None, 1024 * 1024).unwrap();
        let result = client
            .create_contact(
                "test-token",
                "/dav/card/u/default/",
                "a/b",
                "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a/b\r\nFN:Alice\r\nEND:VCARD\r\n",
            )
            .await
            .unwrap();
        assert_eq!(result.href, "/dav/card/u/default/a%2Fb.vcf");
        assert_eq!(result.etag.as_deref(), Some("\"created\""));
    }

    #[tokio::test]
    async fn rejected_bearer_is_not_retried_with_another_auth_scheme() {
        let server = MockServer::start().await;
        Mock::given(method("PROPFIND"))
            .and(path("/.well-known/carddav"))
            .and(header("authorization", "Bearer rejected-token"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bearer rejected"))
            .expect(1)
            .mount(&server)
            .await;
        let client = CardDavClient::new(&server.uri(), None, 1024 * 1024).unwrap();
        let error = client.discover("rejected-token").await.unwrap_err();
        assert!(matches!(error, CardDavError::Unauthorized));
    }

    #[test]
    fn discovery_cache_never_exceeds_its_hard_cap() {
        let client = CardDavClient::new("https://dav.example.test", None, 1024).unwrap();
        let discovery = DavDiscovery {
            principal_href: "/principals/user/".to_owned(),
            addressbook_home_href: "/dav/card/user/".to_owned(),
        };
        for index in 0..(DISCOVERY_CAP + 10) {
            let mut key = [0_u8; 32];
            key[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
            client.discovery_insert(key, &discovery);
        }
        assert_eq!(client.discoveries.read().unwrap().len(), DISCOVERY_CAP);
    }
}
