//! Low-level Hetzner Cloud + Hetzner DNS HTTP client.
//!
//! Responsibilities:
//! - Hold the two credentials (Cloud bearer token, optional DNS `Auth-API-Token`).
//! - Send requests against configurable base URLs (so tests can point at a mock server).
//! - Map Hetzner's documented error envelope (`error.code` / `error.message`) and rate-limit
//!   signals (HTTP 429, `RateLimit-Remaining`) onto [`ProviderError`].
//! - Provide pagination (`page` / `per_page`, following `meta.pagination.next_page`) and
//!   asynchronous action polling (`GET /actions/{id}` until `success`/`error`).
//!
//! Tokens are never logged. Only structural metadata (method, path, status) is traced.

// The trait centralizes error semantics; per-method `# Errors` sections would duplicate it.
#![allow(clippy::missing_errors_doc)]
// `Debug` deliberately omits the token fields (see the impl); not a bug.
#![allow(clippy::missing_fields_in_debug)]
// Const-ness of small helpers is an internal detail and churns across toolchains.
#![allow(clippy::missing_const_for_fn)]

use forge_providers::ProviderError;
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

pub const HETZNER_CLOUD_API: &str = "https://api.hetzner.cloud/v1";
pub const HETZNER_DNS_API: &str = "https://dns.hetzner.com/api/v1";

/// Page size for list endpoints. Hetzner caps `per_page` at 50.
const PER_PAGE: u32 = 50;
/// Max polls before giving up on an action (poll interval below → ~2 min ceiling).
const MAX_ACTION_POLLS: u32 = 120;
const ACTION_POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// Hetzner's standard error envelope: `{ "error": { "code": "...", "message": "..." } }`.
#[derive(Debug, Deserialize)]
struct HetznerErrorEnvelope {
    error: HetznerErrorBody,
}

#[derive(Debug, Deserialize)]
struct HetznerErrorBody {
    code: String,
    message: String,
}

/// A Hetzner async action object (subset).
#[derive(Debug, Deserialize)]
pub struct HetznerAction {
    pub status: String,
    pub error: Option<HetznerActionError>,
}

#[derive(Debug, Deserialize)]
pub struct HetznerActionError {
    pub code: String,
    pub message: String,
}

/// Which Hetzner API a request targets — they use different auth headers.
#[derive(Debug, Clone, Copy)]
pub enum Api {
    Cloud,
    Dns,
}

/// Configurable, mockable Hetzner HTTP client.
#[derive(Clone)]
pub struct HetznerClient {
    http: Client,
    cloud_token: String,
    dns_token: Option<String>,
    cloud_base: String,
    dns_base: String,
    /// In tests we shorten the action poll interval to keep them fast.
    action_poll_interval: Duration,
}

impl std::fmt::Debug for HetznerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose tokens via Debug.
        f.debug_struct("HetznerClient")
            .field("cloud_base", &self.cloud_base)
            .field("dns_base", &self.dns_base)
            .field("dns_configured", &self.dns_token.is_some())
            .finish()
    }
}

impl HetznerClient {
    /// Build a client against the real Hetzner endpoints.
    #[must_use]
    pub fn new(cloud_token: String, dns_token: Option<String>) -> Self {
        Self::with_base_urls(
            cloud_token,
            dns_token,
            HETZNER_CLOUD_API.to_string(),
            HETZNER_DNS_API.to_string(),
        )
    }

    /// Build a client against custom base URLs (used by tests to target a mock server).
    #[must_use]
    pub fn with_base_urls(
        cloud_token: String,
        dns_token: Option<String>,
        cloud_base: String,
        dns_base: String,
    ) -> Self {
        let http = Client::builder()
            .user_agent("forge-provider-hetzner/0.1")
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            http,
            cloud_token,
            dns_token,
            cloud_base,
            dns_base,
            action_poll_interval: ACTION_POLL_INTERVAL,
        }
    }

    /// Override the action poll interval (tests use a near-zero value).
    #[must_use]
    pub fn with_action_poll_interval(mut self, interval: Duration) -> Self {
        self.action_poll_interval = interval;
        self
    }

    /// Whether a Hetzner DNS token was configured (DNS operations require it).
    #[must_use]
    pub fn dns_enabled(&self) -> bool {
        self.dns_token.is_some()
    }

    fn base(&self, api: Api) -> &str {
        match api {
            Api::Cloud => &self.cloud_base,
            Api::Dns => &self.dns_base,
        }
    }

    fn auth(
        &self,
        api: Api,
        req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, ProviderError> {
        match api {
            Api::Cloud => Ok(req.bearer_auth(&self.cloud_token)),
            Api::Dns => {
                let token = self.dns_token.as_ref().ok_or_else(|| {
                    ProviderError::InvalidRequest(
                        "Hetzner DNS token not configured; DNS operations unavailable".to_string(),
                    )
                })?;
                Ok(req.header("Auth-API-Token", token))
            }
        }
    }

    /// Send a request and return the parsed JSON body on success, mapping errors per Hetzner's
    /// envelope. `path` is appended to the API base (must start with `/`).
    pub async fn request(
        &self,
        api: Api,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.base(api), path);
        let mut req = self.http.request(method.clone(), &url);
        req = self.auth(api, req)?;
        if let Some(b) = body {
            req = req.json(b);
        }

        tracing::debug!(method = %method, path = %path, "hetzner request");

        let resp = req.send().await.map_err(|e| map_reqwest_error(&e))?;
        let status = resp.status();

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_secs =
                header_u64(&resp, "Retry-After").or_else(|| header_u64(&resp, "RateLimit-Reset"));
            return Err(ProviderError::RateLimited { retry_after_secs });
        }

        // Treat an exhausted rate-limit budget as a rate-limit error even on a non-429 path,
        // so callers back off before the provider starts rejecting.
        if header_u64(&resp, "RateLimit-Remaining") == Some(0) && !status.is_success() {
            return Err(ProviderError::RateLimited {
                retry_after_secs: header_u64(&resp, "RateLimit-Reset"),
            });
        }

        let text = resp.text().await.map_err(|e| map_reqwest_error(&e))?;

        if status.is_success() {
            if text.trim().is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_str(&text).map_err(|e| {
                ProviderError::Http(format!("failed to decode Hetzner response body: {e}"))
            });
        }

        // Error path: try the documented envelope, fall back to status-derived mapping.
        if let Ok(env) = serde_json::from_str::<HetznerErrorEnvelope>(&text) {
            if status == StatusCode::NOT_FOUND || env.error.code == "not_found" {
                return Err(ProviderError::NotFound(env.error.message));
            }
            return Err(ProviderError::Api {
                status: status.as_u16(),
                code: env.error.code,
                message: env.error.message,
            });
        }

        if status == StatusCode::NOT_FOUND {
            return Err(ProviderError::NotFound(path.to_string()));
        }
        Err(ProviderError::Api {
            status: status.as_u16(),
            code: "unknown".to_string(),
            message: format!("unexpected Hetzner response (status {})", status.as_u16()),
        })
    }

    /// Fetch every page of a list endpoint, concatenating the array under `key`.
    /// `path` must not already contain a query string.
    pub async fn list_all(
        &self,
        api: Api,
        path: &str,
        key: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let sep = if path.contains('?') { '&' } else { '?' };
            let paged = format!("{path}{sep}page={page}&per_page={PER_PAGE}");
            let body = self.request(api, Method::GET, &paged, None).await?;

            if let Some(items) = body.get(key).and_then(Value::as_array) {
                out.extend(items.iter().cloned());
            }

            let next = body
                .get("meta")
                .and_then(|m| m.get("pagination"))
                .and_then(|p| p.get("next_page"))
                .and_then(Value::as_u64);

            match next {
                Some(n) if n > 0 => {
                    page = u32::try_from(n).map_err(|_| {
                        ProviderError::Http("pagination next_page overflow".to_string())
                    })?;
                }
                _ => break,
            }
        }
        Ok(out)
    }

    /// Poll a Cloud action to completion. Returns `Ok(())` on `success`, an error otherwise.
    pub async fn poll_action(&self, action_id: i64) -> Result<(), ProviderError> {
        for _ in 0..MAX_ACTION_POLLS {
            let body = self
                .request(
                    Api::Cloud,
                    Method::GET,
                    &format!("/actions/{action_id}"),
                    None,
                )
                .await?;
            let action: HetznerAction =
                serde_json::from_value(body.get("action").cloned().unwrap_or(Value::Null))
                    .map_err(|e| ProviderError::Http(format!("failed to decode action: {e}")))?;

            match action.status.as_str() {
                "success" => return Ok(()),
                "error" => {
                    let msg = action.error.map_or_else(
                        || "unknown action error".to_string(),
                        |e| format!("{}: {}", e.code, e.message),
                    );
                    return Err(ProviderError::ActionFailed(msg));
                }
                _ => tokio::time::sleep(self.action_poll_interval).await,
            }
        }
        Err(ProviderError::Timeout(format!(
            "action {action_id} did not complete in time"
        )))
    }

    /// Extract an `action` object from a mutation response and poll it to completion.
    pub async fn poll_response_action(&self, body: &Value) -> Result<(), ProviderError> {
        if let Some(id) = body
            .get("action")
            .and_then(|a| a.get("id"))
            .and_then(Value::as_i64)
        {
            return self.poll_action(id).await;
        }
        // Some endpoints return `actions: [..]`; poll all of them.
        if let Some(actions) = body.get("actions").and_then(Value::as_array) {
            for a in actions {
                if let Some(id) = a.get("id").and_then(Value::as_i64) {
                    self.poll_action(id).await?;
                }
            }
            return Ok(());
        }
        Ok(())
    }
}

fn header_u64(resp: &reqwest::Response, name: &str) -> Option<u64> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn map_reqwest_error(e: &reqwest::Error) -> ProviderError {
    if e.is_timeout() {
        ProviderError::Timeout(e.to_string())
    } else {
        // `reqwest::Error::to_string` never contains our tokens (auth is set via headers).
        ProviderError::Http(e.to_string())
    }
}
