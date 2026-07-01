use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use igd_next::{
    AddAnyPortError, PortMappingProtocol, SearchOptions,
    aio::{
        Gateway,
        tokio::{Tokio, search_gateway},
    },
};
use natpmp::{Protocol as NatPmpProtocol, Response as NatPmpResponse, new_tokio_natpmp, new_tokio_natpmp_with};

const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_secs(1);
const UPNP_SEARCH_RESPONSE_TIMEOUT: Duration = Duration::from_millis(300);
const NAT_PMP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

type TokioGateway = Gateway<Tokio>;

/// UPnP端口映射租约
pub struct UpnpPortMappingLease {
    gateway_external_port: u16,
}

impl UpnpPortMappingLease {
    pub fn gateway_external_port(&self) -> u16 {
        self.gateway_external_port
    }
}

/// 尝试打开TCP端口映射
pub async fn try_open_tcp_port(local_port: u16) -> anyhow::Result<Option<UpnpPortMappingLease>> {
    let local_addr = SocketAddr::new("0.0.0.0".parse().unwrap(), local_port);

    // 尝试IGD方式
    match try_igd_mapping(local_addr, PortMappingProtocol::TCP).await {
        Ok(Some(port)) => {
            println!("UPnP IGD TCP端口映射成功: 外部端口 {}", port);
            return Ok(Some(UpnpPortMappingLease {
                gateway_external_port: port,
            }));
        }
        Ok(None) => {
            println!("UPnP IGD端口映射未找到网关");
        }
        Err(e) => {
            println!("UPnP IGD端口映射失败: {}", e);
        }
    }

    // 尝试NAT-PMP方式
    match try_nat_pmp_mapping(local_addr, NatPmpProtocol::TCP).await {
        Ok(Some(port)) => {
            println!("NAT-PMP TCP端口映射成功: 外部端口 {}", port);
            return Ok(Some(UpnpPortMappingLease {
                gateway_external_port: port,
            }));
        }
        Ok(None) => {
            println!("NAT-PMP端口映射未找到网关");
        }
        Err(e) => {
            println!("NAT-PMP端口映射失败: {}", e);
        }
    }

    Ok(None)
}

/// 尝试打开UDP端口映射
pub async fn try_open_udp_port(local_port: u16) -> anyhow::Result<Option<UpnpPortMappingLease>> {
    let local_addr = SocketAddr::new("0.0.0.0".parse().unwrap(), local_port);

    // 尝试IGD方式
    match try_igd_mapping(local_addr, PortMappingProtocol::UDP).await {
        Ok(Some(port)) => {
            println!("UPnP IGD UDP端口映射成功: 外部端口 {}", port);
            return Ok(Some(UpnpPortMappingLease {
                gateway_external_port: port,
            }));
        }
        Ok(None) => {
            println!("UPnP IGD端口映射未找到网关");
        }
        Err(e) => {
            println!("UPnP IGD端口映射失败: {}", e);
        }
    }

    // 尝试NAT-PMP方式
    match try_nat_pmp_mapping(local_addr, NatPmpProtocol::UDP).await {
        Ok(Some(port)) => {
            println!("NAT-PMP UDP端口映射成功: 外部端口 {}", port);
            return Ok(Some(UpnpPortMappingLease {
                gateway_external_port: port,
            }));
        }
        Ok(None) => {
            println!("NAT-PMP端口映射未找到网关");
        }
        Err(e) => {
            println!("NAT-PMP端口映射失败: {}", e);
        }
    }

    Ok(None)
}

/// 尝试通过IGD进行端口映射
async fn try_igd_mapping(local_addr: SocketAddr, protocol: PortMappingProtocol) -> anyhow::Result<Option<u16>> {
    let bind_addr = SocketAddr::new([0, 0, 0, 0].into(), 0);

    let gateway = search_gateway(SearchOptions {
        bind_addr,
        timeout: Some(UPNP_SEARCH_TIMEOUT),
        single_search_timeout: Some(UPNP_SEARCH_RESPONSE_TIMEOUT),
        ..Default::default()
    })
    .await
    .with_context(|| "search igd gateway")?;

    let external_port = gateway
        .add_any_port(
            protocol,
            local_addr,
            300, // 租约时间（秒）
            "nattype tool",
        )
        .await
        .map_err(|e| match e {
            AddAnyPortError::OnlyPermanentLeasesSupported => {
                anyhow!("only permanent leases supported")
            }
            _ => anyhow!("add any port error: {}", e),
        })?;

    Ok(Some(external_port))
}

/// 尝试通过NAT-PMP进行端口映射
async fn try_nat_pmp_mapping(local_addr: SocketAddr, protocol: NatPmpProtocol) -> anyhow::Result<Option<u16>> {
    let client = new_tokio_natpmp().await.context("create nat-pmp client")?;
    let gateway = *client.gateway();

    if gateway == Ipv4Addr::new(0, 0, 0, 0) {
        return Ok(None);
    }

    let client = new_tokio_natpmp_with(gateway)
        .await
        .context("create nat-pmp client with gateway")?;

    // 发送端口映射请求
    client
        .send_port_mapping_request(
            protocol,
            local_addr.port(),
            local_addr.port(),
            300, // 租约时间（秒）
        )
        .await
        .context("send port mapping request")?;

    // 等待响应
    let response = tokio::time::timeout(NAT_PMP_RESPONSE_TIMEOUT, client.read_response_or_retry())
        .await
        .context("timeout waiting for nat-pmp response")?
        .map_err(anyhow::Error::from)
        .context("read nat-pmp response")?;

    match response {
        NatPmpResponse::TCP(mapping) => Ok(Some(mapping.public_port())),
        NatPmpResponse::UDP(mapping) => Ok(Some(mapping.public_port())),
        NatPmpResponse::Gateway(_) => anyhow::bail!("unexpected gateway response"),
    }
}
