//! Integration tests for the Hetzner provider against a mock HTTP server (wiremock).
//!
//! These never touch the real Hetzner API. Each test stands up a `wiremock::MockServer`,
//! points the client's base URLs at it, and serves canned Hetzner JSON.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use forge_provider_hetzner::{HetznerClient, HetznerProvider};
use forge_providers::{
    CloudProvider, DnsRecord, DnsRecordType, ProviderError, ServerId, ServerSpec,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a provider whose Cloud + DNS base URLs both point at `server`, with a near-zero
/// action poll interval so action-polling tests are fast.
fn provider_for(server: &MockServer) -> HetznerProvider {
    let base = server.uri();
    let client = HetznerClient::with_base_urls(
        "test-cloud-token".to_string(),
        Some("test-dns-token".to_string()),
        base.clone(),
        base,
    )
    .with_action_poll_interval(Duration::from_millis(1));
    HetznerProvider::new(client)
}

fn basic_spec(name: &str) -> ServerSpec {
    ServerSpec {
        name: name.to_string(),
        size: "cx22".to_string(),
        image: "ubuntu-24.04".to_string(),
        region: "fsn1".to_string(),
        user_data: Some("#cloud-config\n".to_string()),
        ssh_key_ids: Vec::new(),
        network_ids: Vec::new(),
        firewall_ids: Vec::new(),
        labels: BTreeMap::new(),
    }
}

#[tokio::test]
async fn provision_server_polls_action_to_success() {
    let server = MockServer::start().await;

    // POST /servers -> returns the server + a root action that is still "running".
    Mock::given(method("POST"))
        .and(path("/servers"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "server": {
                "id": 42,
                "name": "web-1",
                "status": "initializing",
                "public_net": { "ipv4": { "ip": "1.2.3.4" }, "ipv6": { "ip": null } },
                "server_type": { "name": "cx22" },
                "datacenter": { "location": { "name": "fsn1" } },
                "image": { "name": "ubuntu-24.04" }
            },
            "action": { "id": 1001, "status": "running" },
            "next_actions": []
        })))
        .mount(&server)
        .await;

    // GET /actions/1001 -> success.
    Mock::given(method("GET"))
        .and(path("/actions/1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "action": { "id": 1001, "status": "success", "error": null }
        })))
        .mount(&server)
        .await;

    // GET /servers/42 -> running, IP populated (read-back after actions complete).
    Mock::given(method("GET"))
        .and(path("/servers/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "server": {
                "id": 42,
                "name": "web-1",
                "status": "running",
                "public_net": { "ipv4": { "ip": "1.2.3.4" }, "ipv6": { "ip": "2a01::1" } },
                "private_net": [],
                "server_type": { "name": "cx22" },
                "datacenter": { "location": { "name": "fsn1" } },
                "image": { "name": "ubuntu-24.04" },
                "labels": { "env": "prod" }
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let info = provider
        .provision_server(&basic_spec("web-1"))
        .await
        .expect("provision should succeed");

    assert_eq!(info.id, ServerId::new("42"));
    assert_eq!(info.public_ipv4.as_deref(), Some("1.2.3.4"));
    assert_eq!(info.public_ipv6.as_deref(), Some("2a01::1"));
    assert_eq!(info.labels.get("env").map(String::as_str), Some("prod"));
}

#[tokio::test]
async fn list_servers_follows_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/servers"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "servers": [{
                "id": 1, "name": "a", "status": "running",
                "public_net": { "ipv4": { "ip": "10.0.0.1" } },
                "server_type": { "name": "cx22" },
                "datacenter": { "location": { "name": "fsn1" } },
                "image": { "name": "ubuntu-24.04" }
            }],
            "meta": { "pagination": { "next_page": 2 } }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/servers"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "servers": [{
                "id": 2, "name": "b", "status": "running",
                "public_net": { "ipv4": { "ip": "10.0.0.2" } },
                "server_type": { "name": "cx22" },
                "datacenter": { "location": { "name": "fsn1" } },
                "image": { "name": "ubuntu-24.04" }
            }],
            "meta": { "pagination": { "next_page": null } }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let servers = provider.list_servers().await.expect("list should succeed");
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].id, ServerId::new("1"));
    assert_eq!(servers[1].id, ServerId::new("2"));
}

#[tokio::test]
async fn rate_limit_429_maps_to_rate_limited() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/servers/7"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "12")
                .set_body_json(json!({
                    "error": { "code": "rate_limit_exceeded", "message": "slow down" }
                })),
        )
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let err = provider
        .get_server(&ServerId::new("7"))
        .await
        .expect_err("should be rate limited");
    match err {
        ProviderError::RateLimited { retry_after_secs } => {
            assert_eq!(retry_after_secs, Some(12));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[tokio::test]
async fn structured_error_body_maps_to_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/servers"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": { "code": "invalid_input", "message": "server_type is invalid" }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let err = provider
        .provision_server(&basic_spec("bad"))
        .await
        .expect_err("should fail with API error");
    match err {
        ProviderError::Api {
            status,
            code,
            message,
        } => {
            assert_eq!(status, 422);
            assert_eq!(code, "invalid_input");
            assert!(message.contains("server_type"));
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[tokio::test]
async fn not_found_maps_to_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/servers/999"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": "not_found", "message": "server not found" }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let err = provider
        .get_server(&ServerId::new("999"))
        .await
        .expect_err("should be not found");
    assert!(matches!(err, ProviderError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn provision_partial_failure_triggers_cleanup() {
    let server = MockServer::start().await;

    // Server is created (id 55) and returns an action that we will fail.
    Mock::given(method("POST"))
        .and(path("/servers"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "server": {
                "id": 55,
                "name": "doomed",
                "status": "initializing",
                "public_net": { "ipv4": { "ip": "1.1.1.1" } },
                "server_type": { "name": "cx22" },
                "datacenter": { "location": { "name": "fsn1" } },
                "image": { "name": "ubuntu-24.04" }
            },
            "action": { "id": 2002, "status": "running" },
            "next_actions": []
        })))
        .mount(&server)
        .await;

    // The provisioning action ends in error -> provider must clean up.
    Mock::given(method("GET"))
        .and(path("/actions/2002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "action": {
                "id": 2002,
                "status": "error",
                "error": { "code": "resource_unavailable", "message": "no capacity" }
            }
        })))
        .mount(&server)
        .await;

    // Cleanup: DELETE /servers/55 must be called. We assert it is hit exactly once and that
    // its own (delete) action is polled to success.
    Mock::given(method("DELETE"))
        .and(path("/servers/55"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "action": { "id": 3003, "status": "running" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/actions/3003"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "action": { "id": 3003, "status": "success", "error": null }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let err = provider
        .provision_server(&basic_spec("doomed"))
        .await
        .expect_err("provision should fail");

    match err {
        ProviderError::PartialFailure {
            created_resource_ids,
            leftover_resource_ids,
            ..
        } => {
            assert_eq!(created_resource_ids, vec!["55".to_string()]);
            // Cleanup succeeded, so nothing left behind.
            assert!(
                leftover_resource_ids.is_empty(),
                "expected clean teardown, leftover: {leftover_resource_ids:?}"
            );
        }
        other => panic!("expected PartialFailure, got {other:?}"),
    }

    // wiremock verifies the DELETE expectation (.expect(1)) on drop.
}

#[tokio::test]
async fn list_sizes_filters_deprecated() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/server_types"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "server_types": [
                {
                    "name": "cx22", "description": "CX22", "cores": 2, "memory": 4.0, "disk": 40.0,
                    "deprecated": false,
                    "prices": [{ "location": "fsn1" }, { "location": "nbg1" }]
                },
                {
                    "name": "cpx11", "description": "old", "cores": 2, "memory": 2.0, "disk": 40.0,
                    "deprecated": true,
                    "prices": [{ "location": "fsn1" }]
                }
            ],
            "meta": { "pagination": { "next_page": null } }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let sizes = provider.list_sizes().await.expect("list_sizes");
    assert_eq!(sizes.len(), 1, "deprecated sizes must be filtered out");
    assert_eq!(sizes[0].id, "cx22");
    assert_eq!(sizes[0].vcpus, 2);
    assert_eq!(sizes[0].available_regions, vec!["fsn1", "nbg1"]);
}

#[tokio::test]
async fn dns_upsert_creates_when_absent() {
    let server = MockServer::start().await;

    // No existing records.
    Mock::given(method("GET"))
        .and(path("/records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [],
            "meta": { "pagination": { "next_page": null } }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "record": { "id": "rec_abc", "type": "A", "name": "www", "value": "1.2.3.4" }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let rec = DnsRecord {
        id: None,
        zone_id: "zone_1".to_string(),
        record_type: DnsRecordType::A,
        name: "www".to_string(),
        value: "1.2.3.4".to_string(),
        ttl: Some(300),
    };
    let id = provider.dns_upsert_record(&rec).await.expect("upsert");
    assert_eq!(id, "rec_abc");
}

#[tokio::test]
async fn ensure_ssh_key_is_idempotent_on_existing_name() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ssh_keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ssh_keys": [{
                "id": 77, "name": "deploy",
                "public_key": "ssh-ed25519 AAAAC3Nz deploy@host"
            }],
            "meta": { "pagination": { "next_page": null } }
        })))
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    // Same name, different comment -> should match existing, NOT create a new one.
    let id = provider
        .ensure_ssh_key("deploy", "ssh-ed25519 AAAAC3Nz other@laptop")
        .await
        .expect("ensure_ssh_key");
    assert_eq!(id, "77");
    // No POST mock is registered; if the provider tried to create, the request would 404.
}

/// Opt-in real-API smoke test. Set `FORGE_HETZNER_TEST_TOKEN` to run:
/// `FORGE_HETZNER_TEST_TOKEN=... cargo test -p forge-provider-hetzner -- --ignored`.
/// Read-only: lists sizes/regions; does not create billable resources.
#[tokio::test]
#[ignore = "hits the real Hetzner API; requires FORGE_HETZNER_TEST_TOKEN"]
async fn real_api_lists_catalog() {
    let Ok(token) = std::env::var("FORGE_HETZNER_TEST_TOKEN") else {
        eprintln!("FORGE_HETZNER_TEST_TOKEN not set; skipping");
        return;
    };
    let provider = HetznerProvider::new(HetznerClient::new(token, None));

    let regions = provider.list_regions().await.expect("list_regions");
    assert!(!regions.is_empty(), "expected at least one region");

    let sizes = provider.list_sizes().await.expect("list_sizes");
    assert!(!sizes.is_empty(), "expected at least one server size");
}
