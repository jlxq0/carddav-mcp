//! `CardDAV` MCP tools over rmcp's streamable-HTTP transport.
//!
//! The HTTP auth middleware places the validated Logto identity and raw bearer
//! in request extensions. Every tool forwards that bearer unchanged to
//! Stalwart through `CardDavClient`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use chrono::{NaiveDate, Utc};
use rand::RngCore as _;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tracing::{Instrument as _, Span};

use crate::audit::{self, outcome};
use crate::auth::AccessToken;
use crate::birthday;
use crate::carddav_client::{CardDavClient, CardDavError, DavContact};
use crate::logto_oidc::{AuthenticatedIdentity, LogtoValidationClient};
use crate::rate_limit::{Category, Limiter};

const MAX_CONTACT_LIMIT: usize = 100;
/// Widest birthday window. A year covers every card exactly once, so anything
/// larger would repeat rather than reveal.
const MAX_BIRTHDAY_DAYS: u32 = 366;
const MAX_VCARD_BYTES: usize = 256 * 1024;
const MAX_CONTACT_FIELD_BYTES: usize = 4096;
const MAX_NOTE_BYTES: usize = 64 * 1024;
const MAX_MULTI_VALUES: usize = 64;

#[derive(Clone)]
pub struct CardDavMcpService {
    carddav: CardDavClient,
    logto: LogtoValidationClient,
    rate_limiter: Arc<Limiter>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for CardDavMcpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardDavMcpService").finish()
    }
}

impl CardDavMcpService {
    pub fn new(
        carddav: CardDavClient,
        logto: LogtoValidationClient,
        rate_limiter: Arc<Limiter>,
    ) -> Self {
        Self {
            carddav,
            logto,
            rate_limiter,
            tool_router: Self::tool_router(),
        }
    }

    fn rate_limit_check(
        &self,
        ctx: &RequestContext<RoleServer>,
        category: Category,
    ) -> Result<(), ErrorData> {
        let token = token_from_ctx(ctx).ok_or_else(missing_token_err)?;
        let identity = identity_from_ctx(ctx).ok_or_else(missing_identity_err)?;
        let bearer_hash = audit::token_hash(&token.0);
        self.rate_limiter
            .check(&bearer_hash, Some(identity.user_id.as_str()), category)
            .map_err(|_| {
                ErrorData::new(
                    rmcp::model::ErrorCode(audit::RATE_LIMITED_CODE),
                    "rate limit exceeded - try again in a minute".to_owned(),
                    None,
                )
            })
    }

    #[allow(clippy::unused_async)]
    async fn react_to_auth_expiry(
        &self,
        ctx: &RequestContext<RoleServer>,
        result: &mut Result<rmcp::model::CallToolResult, ErrorData>,
    ) {
        let Err(error) = result else { return };
        if error.code.0 != audit::AUTH_EXPIRED_CODE {
            return;
        }
        if let Some(AccessToken(token)) = token_from_ctx(ctx) {
            self.carddav.evict(&token);
            self.logto.drop_token(&token);
        }
        *error = ErrorData::new(
            rmcp::model::ErrorCode(audit::AUTH_EXPIRED_CODE),
            "Your carddav-mcp session has expired or Stalwart rejected its bearer. Disconnect and reconnect the MCP client to obtain a fresh Logto token, then retry."
                .to_owned(),
            None,
        );
    }
}

pub fn identity_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AuthenticatedIdentity> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AuthenticatedIdentity>().cloned()
}

pub fn token_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AccessToken> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AccessToken>().cloned()
}

fn structured_result<T: Serialize>(value: &T) -> Result<rmcp::model::CallToolResult, ErrorData> {
    let json = serde_json::to_value(value).map_err(|error| {
        ErrorData::internal_error(format!("serialize tool result: {error}"), None)
    })?;
    Ok(rmcp::model::CallToolResult::structured(json))
}

fn missing_identity_err() -> ErrorData {
    ErrorData::internal_error("no authenticated identity in request context", None)
}

fn missing_token_err() -> ErrorData {
    ErrorData::internal_error("no access token in request context", None)
}

fn map_carddav_err(error: CardDavError) -> ErrorData {
    match error {
        CardDavError::Unauthorized => ErrorData::new(
            rmcp::model::ErrorCode(audit::AUTH_EXPIRED_CODE),
            "auth expired or Stalwart rejected bearer; reconnect".to_owned(),
            None,
        ),
        CardDavError::NotFound
        | CardDavError::Conflict
        | CardDavError::TooLarge
        | CardDavError::InvalidHref(_)
        | CardDavError::InvalidData(_) => ErrorData::invalid_params(error.to_string(), None),
        other => ErrorData::internal_error(other.to_string(), None),
    }
}

fn make_tool_span(tool: &'static str, user: &str, resource: Option<&str>) -> Span {
    tracing::info_span!(
        "mcp.tool",
        tool,
        user,
        resource = resource.unwrap_or(""),
        outcome = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    )
}

fn emit_tool_audit(
    tool: &'static str,
    user: &str,
    resource: Option<&str>,
    started: Instant,
    result_count: Option<usize>,
    span: &Span,
    result: &Result<rmcp::model::CallToolResult, ErrorData>,
) {
    let elapsed = started.elapsed();
    let (outcome_str, error_class) = match result {
        Ok(_) => (outcome::OK, None),
        Err(error) => {
            let class = audit::error_class(error);
            let value = if error.code.0 == audit::RATE_LIMITED_CODE {
                outcome::RATE_LIMITED
            } else {
                outcome::ERROR
            };
            (value, Some(class))
        }
    };
    span.record("outcome", outcome_str);
    span.record(
        "latency_ms",
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    );
    audit::tool_call(
        tool,
        user,
        resource,
        outcome_str,
        started,
        result_count,
        error_class,
    );
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct WhoamiResult {
    pub user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub principal_href: String,
    pub addressbook_home_href: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AddressBookSummary {
    pub id: String,
    pub href: String,
    pub name: String,
    pub ctag: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AddressBooksResult {
    pub address_books: Vec<AddressBookSummary>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListContactsParams {
    /// Address-book href returned by `list_address_books`.
    pub addressbook_href: String,
    /// Maximum contacts returned. Defaults to 25 and is capped at 100.
    #[serde(default = "default_contact_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchContactsParams {
    /// Text matched case-insensitively against name, email, phone, and organisation.
    pub query: String,
    /// Optional address-book href. Omit to search every address book.
    #[serde(default)]
    pub addressbook_href: Option<String>,
    /// Maximum contacts returned across all address books. Defaults to 25, capped at 100.
    #[serde(default = "default_contact_limit")]
    pub limit: usize,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ContactSummary {
    pub href: String,
    pub etag: Option<String>,
    pub uid: Option<String>,
    pub full_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub organization: Option<String>,
    pub title: Option<String>,
    pub note: Option<String>,
    /// `BDAY` as the card stores it. Present so a caller never parses a vCard
    /// for one date; see `upcoming_birthdays` for the window query, which is
    /// what turns four paged calls into one.
    pub birthday: Option<String>,
    pub has_photo: bool,
    /// Original vCard, retained so callers can inspect fields outside the common summary.
    pub vcard: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct UpcomingBirthdaysParams {
    /// Days ahead to include. Today is day 0 and the last day is included, so
    /// 14 covers today plus the next fourteen days. Defaults to 14, capped at 366.
    #[serde(default = "default_birthday_days")]
    pub days: u32,
    /// Optional address-book href. Omit to search every address book.
    #[serde(default)]
    pub addressbook_href: Option<String>,
    /// Reference date as `YYYY-MM-DD`. Omit for today in UTC. Supply it to ask
    /// from a local calendar date, and to get a reproducible answer.
    #[serde(default)]
    pub reference_date: Option<String>,
}

const fn default_birthday_days() -> u32 {
    14
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UpcomingBirthday {
    pub href: String,
    pub uid: Option<String>,
    pub full_name: Option<String>,
    /// `BDAY` exactly as the card stores it.
    pub birthday: String,
    /// `MM-DD`, which is the part that recurs.
    pub month_day: String,
    /// 0 on the day itself.
    pub days_until: u32,
    /// The date it next falls on, `YYYY-MM-DD`, so a caller need not repeat the
    /// leap-day reasoning.
    pub next_occurrence: String,
    /// Age reached at that occurrence, absent when the card records no year.
    /// Absence means unknown; it never means zero.
    pub turning: Option<i32>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UpcomingBirthdaysResult {
    /// Sorted by `days_until`, then by name.
    pub birthdays: Vec<UpcomingBirthday>,
    /// The date the window was measured from, resolved.
    pub reference_date: String,
    pub days: u32,
    /// Cards examined across every address book searched.
    pub contacts_scanned: usize,
    /// Cards carrying a `BDAY` this server could not parse. They are omitted
    /// from `birthdays` rather than failing the call, so a non-zero count here
    /// is the only signal that the answer is incomplete.
    pub unparseable_birthdays: usize,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ContactsResult {
    pub contacts: Vec<ContactSummary>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ContactInput {
    /// Optional stable vCard UID. Generated on create; preserved on update when omitted.
    #[serde(default)]
    pub uid: Option<String>,
    /// Display name (vCard FN). Required and must not be empty.
    pub full_name: String,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub phones: Vec<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateContactParams {
    /// Address-book href returned by `list_address_books`.
    pub addressbook_href: String,
    pub contact: ContactInput,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateContactParams {
    /// Contact href returned by `list_contacts` or `search_contacts`.
    pub contact_href: String,
    /// Optional `ETag` for optimistic concurrency. When omitted, the current
    /// `ETag` is fetched first.
    #[serde(default)]
    pub etag: Option<String>,
    pub contact: ContactInput,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteContactParams {
    /// Contact href returned by `list_contacts` or `search_contacts`.
    pub contact_href: String,
    /// Optional `ETag` for optimistic concurrency. `If-Match: *` is used when omitted.
    #[serde(default)]
    pub etag: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ContactWriteResult {
    pub href: String,
    pub etag: Option<String>,
    pub uid: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DeleteContactResult {
    pub href: String,
    pub deleted: bool,
}

#[tool_router]
impl CardDavMcpService {
    /// Prove the bearer works against Stalwart and return the caller's DAV home.
    #[tool(
        description = "Return the authenticated Logto identity and discovered CardDAV principal/home.",
        annotations(title = "Who am I", read_only_hint = true, idempotent_hint = true)
    )]
    async fn whoami(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = identity
            .as_ref()
            .and_then(|value| value.email.clone())
            .unwrap_or_default();
        let span = make_tool_span("whoami", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let identity = identity.ok_or_else(missing_identity_err)?;
            let discovery = self
                .carddav
                .discover(&token.0)
                .await
                .map_err(map_carddav_err)?;
            structured_result(&WhoamiResult {
                user_id: identity.user_id,
                email: identity.email,
                name: identity.name,
                principal_href: discovery.principal_href,
                addressbook_home_href: discovery.addressbook_home_href,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit("whoami", &user, None, started, None, &span, &result);
        result
    }

    #[tool(
        description = "List every CardDAV address book available to the authenticated user.",
        annotations(
            title = "List address books",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn list_address_books(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|identity| identity.email)
            .unwrap_or_default();
        let span = make_tool_span("list_address_books", &user, None);
        let mut count = None;
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let books = self
                .carddav
                .list_address_books(&token.0)
                .await
                .map_err(map_carddav_err)?
                .into_iter()
                .map(|book| AddressBookSummary {
                    id: href_id(&book.href),
                    href: book.href,
                    name: book.display_name,
                    ctag: book.ctag,
                })
                .collect::<Vec<_>>();
            count = Some(books.len());
            structured_result(&AddressBooksResult {
                address_books: books,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "list_address_books",
            &user,
            None,
            started,
            count,
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "List contacts in one address book. Use list_address_books first to obtain its href.",
        annotations(title = "List contacts", read_only_hint = true, idempotent_hint = true)
    )]
    async fn list_contacts(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListContactsParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|identity| identity.email)
            .unwrap_or_default();
        let resource = params.addressbook_href.clone();
        let span = make_tool_span("list_contacts", &user, Some(&resource));
        let mut count = None;
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let limit = validated_limit(params.limit)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let contacts = self
                .carddav
                .list_contacts(&token.0, &params.addressbook_href)
                .await
                .map_err(map_carddav_err)?
                .into_iter()
                .take(limit)
                .map(contact_summary)
                .collect::<Vec<_>>();
            count = Some(contacts.len());
            structured_result(&ContactsResult { contacts })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "list_contacts",
            &user,
            Some(&resource),
            started,
            count,
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "List contacts whose birthday falls within the next N days, across one or all address books. One call; do not page list_contacts and parse vCards for this.",
        annotations(
            title = "Upcoming birthdays",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn upcoming_birthdays(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpcomingBirthdaysParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|identity| identity.email)
            .unwrap_or_default();
        let resource = params.addressbook_href.clone();
        let span = make_tool_span("upcoming_birthdays", &user, resource.as_deref());
        let mut count = None;
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            if params.days == 0 || params.days > MAX_BIRTHDAY_DAYS {
                return Err(ErrorData::invalid_params(
                    format!("`days` must be between 1 and {MAX_BIRTHDAY_DAYS}"),
                    None,
                ));
            }
            let today = match &params.reference_date {
                Some(raw) => NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d").map_err(|_| {
                    ErrorData::invalid_params("`reference_date` must be YYYY-MM-DD", None)
                })?,
                None => Utc::now().date_naive(),
            };
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let hrefs = if let Some(href) = &params.addressbook_href {
                vec![href.clone()]
            } else {
                self.carddav
                    .list_address_books(&token.0)
                    .await
                    .map_err(map_carddav_err)?
                    .into_iter()
                    .map(|book| book.href)
                    .collect()
            };

            let mut birthdays = Vec::new();
            let mut scanned = 0usize;
            let mut unparseable = 0usize;
            for href in hrefs {
                let contacts = self
                    .carddav
                    .list_contacts(&token.0, &href)
                    .await
                    .map_err(map_carddav_err)?;
                for contact in contacts {
                    scanned += 1;
                    let parsed = parse_vcard(&contact.vcard);
                    let Some(raw) = parsed.birthday else {
                        continue;
                    };
                    let Some(bday) = birthday::parse_bday(&raw) else {
                        unparseable += 1;
                        continue;
                    };
                    // The window decision lives in `birthday::within_window`
                    // and is made nowhere else, so the fixture that pins it is
                    // pinning this call rather than a copy of it.
                    let Some(days_until) = birthday::within_window(&bday, today, params.days)
                    else {
                        continue;
                    };
                    let next = today + chrono::Duration::days(i64::from(days_until));
                    birthdays.push(UpcomingBirthday {
                        href: contact.href,
                        uid: parsed.uid,
                        full_name: parsed.full_name,
                        month_day: format!("{:02}-{:02}", bday.month, bday.day),
                        birthday: bday.raw.clone(),
                        days_until,
                        next_occurrence: next.format("%Y-%m-%d").to_string(),
                        turning: birthday::turning(&bday, today),
                    });
                }
            }
            birthdays.sort_by(|a, b| {
                a.days_until
                    .cmp(&b.days_until)
                    .then_with(|| a.full_name.cmp(&b.full_name))
            });
            count = Some(birthdays.len());
            structured_result(&UpcomingBirthdaysResult {
                birthdays,
                reference_date: today.format("%Y-%m-%d").to_string(),
                days: params.days,
                contacts_scanned: scanned,
                unparseable_birthdays: unparseable,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "upcoming_birthdays",
            &user,
            resource.as_deref(),
            started,
            count,
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Search contacts by name, email, phone, or organisation in one or all address books.",
        annotations(
            title = "Search contacts",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn search_contacts(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SearchContactsParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|identity| identity.email)
            .unwrap_or_default();
        let resource = params.addressbook_href.clone();
        let span = make_tool_span("search_contacts", &user, resource.as_deref());
        let mut count = None;
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let limit = validated_limit(params.limit)?;
            if params.query.trim().is_empty() {
                return Err(ErrorData::invalid_params("`query` must not be empty", None));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let hrefs = if let Some(href) = &params.addressbook_href {
                vec![href.clone()]
            } else {
                self.carddav
                    .list_address_books(&token.0)
                    .await
                    .map_err(map_carddav_err)?
                    .into_iter()
                    .map(|book| book.href)
                    .collect()
            };
            let mut seen = HashSet::new();
            let mut contacts = Vec::new();
            for href in hrefs {
                let matches = self
                    .carddav
                    .search_contacts(&token.0, &href, &params.query)
                    .await
                    .map_err(map_carddav_err)?;
                for contact in matches {
                    if seen.insert(contact.href.clone()) {
                        contacts.push(contact_summary(contact));
                    }
                    if contacts.len() >= limit {
                        break;
                    }
                }
                if contacts.len() >= limit {
                    break;
                }
            }
            count = Some(contacts.len());
            structured_result(&ContactsResult { contacts })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "search_contacts",
            &user,
            resource.as_deref(),
            started,
            count,
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Create a contact in an address book. The write is protected with If-None-Match.",
        annotations(
            title = "Create contact",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn create_contact(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateContactParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|identity| identity.email)
            .unwrap_or_default();
        let resource = params.addressbook_href.clone();
        let span = make_tool_span("create_contact", &user, Some(&resource));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            validate_contact_input(&params.contact)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let uid = params.contact.uid.clone().unwrap_or_else(generate_uid);
            validate_uid(&uid)?;
            let vcard = build_vcard(&params.contact, &uid)?;
            let written = self
                .carddav
                .create_contact(&token.0, &params.addressbook_href, &uid, &vcard)
                .await
                .map_err(map_carddav_err)?;
            structured_result(&ContactWriteResult {
                href: written.href,
                etag: written.etag,
                uid,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "create_contact",
            &user,
            Some(&resource),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Replace a contact's common vCard fields while preserving its UID. Uses ETag concurrency control.",
        annotations(
            title = "Update contact",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn update_contact(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateContactParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|identity| identity.email)
            .unwrap_or_default();
        let resource = params.contact_href.clone();
        let span = make_tool_span("update_contact", &user, Some(&resource));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            validate_contact_input(&params.contact)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let existing = self
                .carddav
                .get_contact(&token.0, &params.contact_href)
                .await
                .map_err(map_carddav_err)?;
            let existing_uid = parse_vcard(&existing.vcard).uid.ok_or_else(|| {
                ErrorData::invalid_params("existing vCard has no UID; refusing replacement", None)
            })?;
            if params
                .contact
                .uid
                .as_ref()
                .is_some_and(|uid| uid != &existing_uid)
            {
                return Err(ErrorData::invalid_params(
                    "contact UID cannot be changed during update",
                    None,
                ));
            }
            let vcard = build_vcard(&params.contact, &existing_uid)?;
            let etag = params.etag.as_deref().or(existing.etag.as_deref());
            let written = self
                .carddav
                .update_contact(&token.0, &params.contact_href, etag, &vcard)
                .await
                .map_err(map_carddav_err)?;
            structured_result(&ContactWriteResult {
                href: written.href,
                etag: written.etag,
                uid: existing_uid,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "update_contact",
            &user,
            Some(&resource),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Permanently delete one CardDAV contact by href, optionally requiring its current ETag.",
        annotations(
            title = "Delete contact",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn delete_contact(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<DeleteContactParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|identity| identity.email)
            .unwrap_or_default();
        let resource = params.contact_href.clone();
        let span = make_tool_span("delete_contact", &user, Some(&resource));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            self.carddav
                .delete_contact(&token.0, &params.contact_href, params.etag.as_deref())
                .await
                .map_err(map_carddav_err)?;
            structured_result(&DeleteContactResult {
                href: params.contact_href,
                deleted: true,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "delete_contact",
            &user,
            Some(&resource),
            started,
            None,
            &span,
            &result,
        );
        result
    }
}

// `tool_handler` generates the async trait method required by rmcp. Rust 1.98's
// Clippy cannot see the awaited work inside that macro expansion and reports
// `unused_async_trait_impl`; older supported compilers do not know the lint.
#[allow(unknown_lints, clippy::unused_async_trait_impl)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for CardDavMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "carddav-mcp: list, search, create, update, and delete contacts in the authenticated user's Stalwart CardDAV address books. Call list_address_books first and pass its hrefs to contact tools.",
        )
    }
}

const fn default_contact_limit() -> usize {
    25
}

fn validated_limit(limit: usize) -> Result<usize, ErrorData> {
    if limit == 0 {
        return Err(ErrorData::invalid_params(
            "`limit` must be greater than zero",
            None,
        ));
    }
    Ok(limit.min(MAX_CONTACT_LIMIT))
}

fn href_id(href: &str) -> String {
    href.trim_end_matches('/')
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(href)
        .to_owned()
}

fn contact_summary(contact: DavContact) -> ContactSummary {
    let parsed = parse_vcard(&contact.vcard);
    ContactSummary {
        href: contact.href,
        etag: contact.etag,
        uid: parsed.uid,
        full_name: parsed.full_name,
        given_name: parsed.given_name,
        family_name: parsed.family_name,
        emails: parsed.emails,
        phones: parsed.phones,
        organization: parsed.organization,
        title: parsed.title,
        note: parsed.note,
        birthday: parsed.birthday,
        has_photo: parsed.has_photo,
        vcard: contact.vcard,
    }
}

#[derive(Default)]
struct ParsedVcard {
    uid: Option<String>,
    full_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    emails: Vec<String>,
    phones: Vec<String>,
    organization: Option<String>,
    title: Option<String>,
    note: Option<String>,
    birthday: Option<String>,
    has_photo: bool,
}

fn parse_vcard(vcard: &str) -> ParsedVcard {
    let mut parsed = ParsedVcard::default();
    for line in unfold_vcard_lines(vcard) {
        let Some((head, raw_value)) = line.split_once(':') else {
            continue;
        };
        let property = head
            .split(';')
            .next()
            .unwrap_or_default()
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let value = unescape_vcard_text(raw_value);
        match property.as_str() {
            "UID" => parsed.uid = Some(value),
            "FN" => parsed.full_name = Some(value),
            "N" => {
                let mut parts = raw_value.split(';').map(unescape_vcard_text);
                parsed.family_name = parts.next().filter(|part| !part.is_empty());
                parsed.given_name = parts.next().filter(|part| !part.is_empty());
            }
            "EMAIL" => parsed
                .emails
                .push(value.strip_prefix("mailto:").unwrap_or(&value).to_owned()),
            "TEL" => parsed
                .phones
                .push(value.strip_prefix("tel:").unwrap_or(&value).to_owned()),
            "ORG" => {
                parsed.organization = value.split(';').next().map(ToOwned::to_owned);
            }
            "TITLE" => parsed.title = Some(value),
            "NOTE" => parsed.note = Some(value),
            "BDAY" => parsed.birthday = Some(value),
            "PHOTO" => parsed.has_photo = true,
            _ => {}
        }
    }
    parsed
}

fn unfold_vcard_lines(vcard: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in vcard.replace("\r\n", "\n").split('\n') {
        if raw.starts_with([' ', '\t']) {
            if let Some(previous) = lines.last_mut() {
                previous.push_str(&raw[1..]);
            }
        } else {
            lines.push(raw.trim_end_matches('\r').to_owned());
        }
    }
    lines
}

fn unescape_vcard_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => output.push('\n'),
            Some(next) => output.push(next),
            None => output.push('\\'),
        }
    }
    output
}

fn escape_vcard_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\r', "")
        .replace('\n', "\\n")
        .replace(';', "\\;")
        .replace(',', "\\,")
}

fn validate_contact_input(contact: &ContactInput) -> Result<(), ErrorData> {
    if contact.full_name.trim().is_empty() {
        return Err(ErrorData::invalid_params(
            "`contact.full_name` must not be empty",
            None,
        ));
    }
    for (name, value, max) in [
        (
            "full_name",
            Some(&contact.full_name),
            MAX_CONTACT_FIELD_BYTES,
        ),
        (
            "given_name",
            contact.given_name.as_ref(),
            MAX_CONTACT_FIELD_BYTES,
        ),
        (
            "family_name",
            contact.family_name.as_ref(),
            MAX_CONTACT_FIELD_BYTES,
        ),
        (
            "organization",
            contact.organization.as_ref(),
            MAX_CONTACT_FIELD_BYTES,
        ),
        ("title", contact.title.as_ref(), MAX_CONTACT_FIELD_BYTES),
        ("note", contact.note.as_ref(), MAX_NOTE_BYTES),
    ] {
        if value.is_some_and(|value| value.len() > max) {
            return Err(ErrorData::invalid_params(
                format!("`contact.{name}` exceeds {max} bytes"),
                None,
            ));
        }
    }
    if contact.emails.len() > MAX_MULTI_VALUES || contact.phones.len() > MAX_MULTI_VALUES {
        return Err(ErrorData::invalid_params(
            format!("contacts may contain at most {MAX_MULTI_VALUES} emails and phone numbers"),
            None,
        ));
    }
    if contact
        .emails
        .iter()
        .chain(&contact.phones)
        .any(|value| value.len() > MAX_CONTACT_FIELD_BYTES)
    {
        return Err(ErrorData::invalid_params(
            "an email or phone value exceeds the field-size limit",
            None,
        ));
    }
    if let Some(uid) = &contact.uid {
        validate_uid(uid)?;
    }
    Ok(())
}

fn validate_uid(uid: &str) -> Result<(), ErrorData> {
    if uid.trim().is_empty() || uid.len() > 512 || uid.chars().any(char::is_control) {
        return Err(ErrorData::invalid_params(
            "contact UID must be 1-512 bytes and contain no control characters",
            None,
        ));
    }
    Ok(())
}

fn generate_uid() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{}@carddav-mcp", hex::encode(bytes))
}

fn build_vcard(contact: &ContactInput, uid: &str) -> Result<String, ErrorData> {
    validate_uid(uid)?;
    let mut lines = vec![
        "BEGIN:VCARD".to_owned(),
        "VERSION:4.0".to_owned(),
        format!("UID:{}", escape_vcard_text(uid)),
        format!("FN:{}", escape_vcard_text(&contact.full_name)),
        format!(
            "N:{};{};;;",
            escape_vcard_text(contact.family_name.as_deref().unwrap_or_default()),
            escape_vcard_text(contact.given_name.as_deref().unwrap_or_default())
        ),
    ];
    for email in &contact.emails {
        lines.push(format!("EMAIL:{}", escape_vcard_text(email)));
    }
    for phone in &contact.phones {
        lines.push(format!("TEL:{}", escape_vcard_text(phone)));
    }
    if let Some(organization) = nonempty(contact.organization.as_deref()) {
        lines.push(format!("ORG:{}", escape_vcard_text(organization)));
    }
    if let Some(title) = nonempty(contact.title.as_deref()) {
        lines.push(format!("TITLE:{}", escape_vcard_text(title)));
    }
    if let Some(note) = nonempty(contact.note.as_deref()) {
        lines.push(format!("NOTE:{}", escape_vcard_text(note)));
    }
    lines.push("END:VCARD".to_owned());

    let mut vcard = String::new();
    for line in lines {
        vcard.push_str(&fold_vcard_line(&line));
        vcard.push_str("\r\n");
    }
    if vcard.len() > MAX_VCARD_BYTES {
        return Err(ErrorData::invalid_params(
            format!("generated vCard exceeds {MAX_VCARD_BYTES} bytes"),
            None,
        ));
    }
    Ok(vcard)
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn fold_vcard_line(line: &str) -> String {
    if line.len() <= 75 {
        return line.to_owned();
    }
    let mut output = String::new();
    let mut remaining = line;
    let mut first = true;
    while !remaining.is_empty() {
        let max = if first { 75 } else { 74 };
        let mut split = remaining.len().min(max);
        while !remaining.is_char_boundary(split) {
            split -= 1;
        }
        if !first {
            output.push_str("\r\n ");
        }
        output.push_str(&remaining[..split]);
        remaining = &remaining[split..];
        first = false;
    }
    output
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn contact() -> ContactInput {
        ContactInput {
            uid: None,
            full_name: "Alice Example".to_owned(),
            given_name: Some("Alice".to_owned()),
            family_name: Some("Example".to_owned()),
            emails: vec!["alice@kanjo.sg".to_owned()],
            phones: vec!["+65 6123 4567".to_owned()],
            organization: Some("Kampong Social Club".to_owned()),
            title: Some("Member".to_owned()),
            note: Some("Line one\nLine two".to_owned()),
        }
    }

    #[test]
    fn vcard_round_trip_extracts_common_fields() {
        let vcard = build_vcard(&contact(), "alice-1@carddav-mcp").unwrap();
        assert!(vcard.ends_with("END:VCARD\r\n"));
        let parsed = parse_vcard(&vcard);
        assert_eq!(parsed.uid.as_deref(), Some("alice-1@carddav-mcp"));
        assert_eq!(parsed.full_name.as_deref(), Some("Alice Example"));
        assert_eq!(parsed.given_name.as_deref(), Some("Alice"));
        assert_eq!(parsed.family_name.as_deref(), Some("Example"));
        assert_eq!(parsed.emails, vec!["alice@kanjo.sg"]);
        assert_eq!(parsed.note.as_deref(), Some("Line one\nLine two"));
    }

    #[test]
    fn vcard_escaping_blocks_property_injection() {
        let mut input = contact();
        input.full_name = "Alice\r\nEMAIL:attacker@evil.test".to_owned();
        let vcard = build_vcard(&input, "safe-id").unwrap();
        assert!(vcard.contains("FN:Alice\\nEMAIL:attacker@evil.test"));
        assert_eq!(
            vcard
                .lines()
                .filter(|line| line.starts_with("EMAIL:"))
                .count(),
            1
        );
    }

    #[test]
    fn folded_utf8_lines_unfold_without_corruption() {
        let mut input = contact();
        input.note = Some("界".repeat(80));
        let vcard = build_vcard(&input, "utf8-id").unwrap();
        assert!(vcard.contains("\r\n "));
        let parsed = parse_vcard(&vcard);
        assert_eq!(parsed.note, input.note);
    }

    #[test]
    fn list_limit_is_bounded() {
        assert_eq!(validated_limit(1000).unwrap(), MAX_CONTACT_LIMIT);
        assert!(validated_limit(0).is_err());
    }
}
