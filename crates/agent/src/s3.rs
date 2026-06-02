//! Minimal AWS Signature Version 4 client for S3-compatible object storage.
//!
//! Used by the backup/restore executor to PUT a dump to (and GET it back from) operator-
//! configured object storage (MinIO, Hetzner Object Storage, AWS S3, …). We sign with
//! SigV4 (HMAC-SHA256) so uploads/downloads work against real, authenticated buckets —
//! the previous unsigned PUT only worked against anonymous buckets.
//!
//! Security:
//! - The endpoint MUST be `https` (checked in [`S3Client::new`]); we never speak plaintext
//!   to object storage carrying a backup.
//! - Credentials (`secret_key`) are never logged and never placed in an error string
//!   (OWASP A09). They live only in the signing computation.
//! - SSRF is low-risk here (the endpoint is operator-configured, not user-supplied), but we
//!   still validate the scheme + bound the length, matching the control-plane policy.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// S3 request/credential error. Deliberately coarse and secret-free.
#[derive(Debug, thiserror::Error)]
pub enum S3Error {
    #[error("invalid endpoint")]
    InvalidEndpoint,
    #[error("request failed")]
    Request,
    #[error("object storage returned status {0}")]
    Status(u16),
}

/// A signed-request client bound to one S3-compatible endpoint + bucket.
pub struct S3Client {
    endpoint: String,
    bucket: String,
    region: String,
    access_key_id: String,
    secret_key: String,
    http: reqwest::Client,
}

impl S3Client {
    /// Build a client. `endpoint` must be an https URL (e.g. `https://s3.eu-central-1.example`).
    /// Path-style addressing is used (`endpoint/bucket/key`) so it works with MinIO and most
    /// S3-compatibles without DNS bucket subdomains.
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: Option<&str>,
        access_key_id: &str,
        secret_key: &str,
    ) -> Result<Self, S3Error> {
        let endpoint = endpoint.trim().trim_end_matches('/');
        if endpoint.len() > 2048 || !endpoint.starts_with("https://") {
            return Err(S3Error::InvalidEndpoint);
        }
        if bucket.trim().is_empty() {
            return Err(S3Error::InvalidEndpoint);
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|_| S3Error::Request)?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            bucket: bucket.trim().to_string(),
            region: region.unwrap_or("us-east-1").to_string(),
            access_key_id: access_key_id.to_string(),
            secret_key: secret_key.to_string(),
            http,
        })
    }

    /// The path-style host + canonical path for `key` (no leading slash on the key segments).
    fn object_url(&self, key: &str) -> String {
        let key = key.trim_start_matches('/');
        format!("{}/{}/{}", self.endpoint, self.bucket, key)
    }

    /// Host header value (authority) for the endpoint, used in the canonical request.
    fn host(&self) -> Result<String, S3Error> {
        let url = reqwest::Url::parse(&self.endpoint).map_err(|_| S3Error::InvalidEndpoint)?;
        let host = url.host_str().ok_or(S3Error::InvalidEndpoint)?;
        Ok(match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        })
    }

    /// PUT `body` to `key`. Returns the `s3://bucket/key` location on success.
    pub async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<String, S3Error> {
        let key = key.trim_start_matches('/');
        let payload_hash = hex::encode(Sha256::digest(&body));
        let canonical_uri = format!("/{}/{}", self.bucket, key);
        let headers = self.sign("PUT", &canonical_uri, &payload_hash)?;

        let mut req = self
            .http
            .put(self.object_url(key))
            .header("content-type", "application/octet-stream");
        for (k, v) in &headers {
            req = req.header(k, v);
        }
        let resp = req.body(body).send().await.map_err(|_| S3Error::Request)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(S3Error::Status(status.as_u16()));
        }
        Ok(format!("s3://{}/{}", self.bucket, key))
    }

    /// GET `key` and return its bytes.
    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        let key = key.trim_start_matches('/');
        // GET has an empty body; its payload hash is the SHA256 of the empty string.
        let payload_hash = hex::encode(Sha256::digest(b""));
        let canonical_uri = format!("/{}/{}", self.bucket, key);
        let headers = self.sign("GET", &canonical_uri, &payload_hash)?;

        let mut req = self.http.get(self.object_url(key));
        for (k, v) in &headers {
            req = req.header(k, v);
        }
        let resp = req.send().await.map_err(|_| S3Error::Request)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(S3Error::Status(status.as_u16()));
        }
        let bytes = resp.bytes().await.map_err(|_| S3Error::Request)?;
        Ok(bytes.to_vec())
    }

    /// Compute SigV4 auth headers for `method`/`canonical_uri` with the given payload hash.
    /// Returns the headers to attach (`host`, `x-amz-date`, `x-amz-content-sha256`,
    /// `authorization`). Never includes the secret key.
    fn sign(
        &self,
        method: &str,
        canonical_uri: &str,
        payload_hash: &str,
    ) -> Result<Vec<(String, String)>, S3Error> {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let host = self.host()?;
        let service = "s3";

        // S3 requires URI-path encoding of each segment; our keys are control-plane-generated
        // (`prefix/dump-<uuid>.sql`) with safe chars, so the path is used as-is. We still
        // percent-encode spaces defensively.
        let canonical_uri = canonical_uri.replace(' ', "%20");

        let canonical_headers =
            format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        let canonical_request = format!(
            "{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

        let credential_scope = format!("{date_stamp}/{}/{service}/aws4_request", self.region);
        let string_to_sign =
            format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

        let signing_key = self.derive_signing_key(&date_stamp, service)?;
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        );

        Ok(vec![
            ("host".to_string(), host),
            ("x-amz-date".to_string(), amz_date),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("authorization".to_string(), authorization),
        ])
    }

    /// SigV4 key derivation: HMAC chain rooted at `AWS4` + secret key.
    fn derive_signing_key(&self, date_stamp: &str, service: &str) -> Result<Vec<u8>, S3Error> {
        let k_secret = format!("AWS4{}", self.secret_key);
        let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes())?;
        let k_region = hmac_sha256(&k_date, self.region.as_bytes())?;
        let k_service = hmac_sha256(&k_region, service.as_bytes())?;
        hmac_sha256(&k_service, b"aws4_request")
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, S3Error> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| S3Error::Request)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_endpoint() {
        assert!(matches!(
            S3Client::new("http://insecure.example", "b", None, "ak", "sk"),
            Err(S3Error::InvalidEndpoint)
        ));
    }

    #[test]
    fn rejects_empty_bucket() {
        assert!(matches!(
            S3Client::new("https://s3.example", "  ", None, "ak", "sk"),
            Err(S3Error::InvalidEndpoint)
        ));
    }

    #[test]
    fn builds_path_style_url() {
        let c = S3Client::new("https://s3.example/", "backups", None, "ak", "sk").unwrap();
        assert_eq!(
            c.object_url("/a/b.sql"),
            "https://s3.example/backups/a/b.sql"
        );
    }

    #[test]
    fn signature_is_deterministic_shape_and_secret_free() {
        let c = S3Client::new("https://s3.example", "b", Some("eu"), "AKID", "TOPSECRET").unwrap();
        let hash = hex::encode(Sha256::digest(b""));
        let headers = c.sign("GET", "/b/k", &hash).unwrap();
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"));
        // The secret key must never appear anywhere in the produced headers.
        for (_, v) in &headers {
            assert!(!v.contains("TOPSECRET"), "secret leaked into header: {v}");
        }
    }

    #[test]
    fn known_signing_key_vector() {
        // AWS-published SigV4 key-derivation test vector (Signature Version 4 docs):
        //   secret = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
        //   date   = 20150830, region = us-east-1, service = iam
        // expected kSigning =
        //   c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9
        // Asserting against the canonical vector proves the HMAC chain is correct.
        let c = S3Client::new(
            "https://s3.example",
            "b",
            Some("us-east-1"),
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        )
        .unwrap();
        let key = c.derive_signing_key("20150830", "iam").unwrap();
        assert_eq!(
            hex::encode(key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }
}
