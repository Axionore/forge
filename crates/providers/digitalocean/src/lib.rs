//! `DigitalOcean` cloud provider scaffold — implement in a future state.
//!
//! Every [`CloudProvider`] method returns [`ProviderError::NotImplemented`] and
//! [`CloudProvider::capabilities`] reports no capabilities. This is an intentional scaffold,
//! not a partial implementation: it compiles and lets the control plane list `DigitalOcean` as
//! "coming soon" without special-casing a missing provider.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use forge_providers::{
    Capabilities, CloudProvider, DnsRecord, FirewallRule, ImageInfo, LbService, LbTarget,
    LoadBalancerInfo, NetworkInfo, ProviderError, RegionInfo, Result, ServerId, ServerInfo,
    ServerSpec, SizeInfo, VolumeInfo,
};

/// `DigitalOcean` provider scaffold. See the module docs.
#[derive(Debug, Clone, Default)]
pub struct DigitalOceanProvider;

#[async_trait]
impl CloudProvider for DigitalOceanProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities::none()
    }

    async fn list_regions(&self) -> Result<Vec<RegionInfo>> {
        Err(ProviderError::NotImplemented)
    }
    async fn list_sizes(&self) -> Result<Vec<SizeInfo>> {
        Err(ProviderError::NotImplemented)
    }
    async fn list_images(&self) -> Result<Vec<ImageInfo>> {
        Err(ProviderError::NotImplemented)
    }
    async fn provision_server(&self, _spec: &ServerSpec) -> Result<ServerInfo> {
        Err(ProviderError::NotImplemented)
    }
    async fn get_server(&self, _id: &ServerId) -> Result<ServerInfo> {
        Err(ProviderError::NotImplemented)
    }
    async fn list_servers(&self) -> Result<Vec<ServerInfo>> {
        Err(ProviderError::NotImplemented)
    }
    async fn delete_server(&self, _id: &ServerId) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn resize_server(
        &self,
        _id: &ServerId,
        _new_size: &str,
        _upgrade_disk: bool,
    ) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn rebuild_server(&self, _id: &ServerId, _image: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn ensure_ssh_key(&self, _name: &str, _public_key: &str) -> Result<String> {
        Err(ProviderError::NotImplemented)
    }
    async fn list_ssh_keys(&self) -> Result<Vec<(String, String)>> {
        Err(ProviderError::NotImplemented)
    }
    async fn delete_ssh_key(&self, _id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn create_network(&self, _name: &str, _ip_range: &str) -> Result<NetworkInfo> {
        Err(ProviderError::NotImplemented)
    }
    async fn delete_network(&self, _id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn list_networks(&self) -> Result<Vec<NetworkInfo>> {
        Err(ProviderError::NotImplemented)
    }
    async fn attach_server_to_network(&self, _server: &ServerId, _network_id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn create_firewall(&self, _name: &str, _rules: &[FirewallRule]) -> Result<String> {
        Err(ProviderError::NotImplemented)
    }
    async fn delete_firewall(&self, _id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn attach_firewall(&self, _firewall_id: &str, _server: &ServerId) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn detach_firewall(&self, _firewall_id: &str, _server: &ServerId) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn allocate_ip(&self, _region: &str, _ipv6: bool) -> Result<(String, String)> {
        Err(ProviderError::NotImplemented)
    }
    async fn assign_ip(&self, _ip_id: &str, _server: &ServerId) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn release_ip(&self, _ip_id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn create_volume(&self, _name: &str, _size_gb: u64, _region: &str) -> Result<VolumeInfo> {
        Err(ProviderError::NotImplemented)
    }
    async fn attach_volume(&self, _volume_id: &str, _server: &ServerId) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn detach_volume(&self, _volume_id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn resize_volume(&self, _volume_id: &str, _new_size_gb: u64) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn delete_volume(&self, _volume_id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn create_load_balancer(
        &self,
        _name: &str,
        _region: &str,
        _services: &[LbService],
    ) -> Result<LoadBalancerInfo> {
        Err(ProviderError::NotImplemented)
    }
    async fn delete_load_balancer(&self, _id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn add_lb_target(&self, _lb_id: &str, _target: &LbTarget) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn remove_lb_target(&self, _lb_id: &str, _server: &ServerId) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn update_lb_service(&self, _lb_id: &str, _service: &LbService) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn dns_ensure_zone(&self, _domain: &str) -> Result<String> {
        Err(ProviderError::NotImplemented)
    }
    async fn dns_upsert_record(&self, _record: &DnsRecord) -> Result<String> {
        Err(ProviderError::NotImplemented)
    }
    async fn dns_delete_record(&self, _zone_id: &str, _record_id: &str) -> Result<()> {
        Err(ProviderError::NotImplemented)
    }
    async fn dns_list_records(&self, _zone_id: &str) -> Result<Vec<DnsRecord>> {
        Err(ProviderError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capabilities_are_empty() {
        assert_eq!(DigitalOceanProvider.capabilities(), Capabilities::none());
    }

    #[tokio::test]
    async fn every_call_is_not_implemented() {
        let p = DigitalOceanProvider;
        assert!(matches!(
            p.list_regions().await,
            Err(ProviderError::NotImplemented)
        ));
        assert!(matches!(
            p.get_server(&ServerId::new("x")).await,
            Err(ProviderError::NotImplemented)
        ));
    }
}
