use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::UdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
use stun_codec::rfc5389::methods::BINDING;

use crate::nat_type::NatType;
use crate::stun::StunClientBuilder;
use crate::stun_codec_ext::*;
use crate::upnp;

/// 端口测试服务器
const PORT_TEST_SERVER: &str = "portcheck.transmissionbt.com";

/// 默认UDP STUN服务器（需要支持RFC3489的change_ip/change_port）
const DEFAULT_UDP_STUN_SERVERS: &[&str] = &[
    "stun.miwifi.com:3478",
    "stun.chat.bilibili.com:3478",
    "stun.hitv.com:3478",
    "stun.cdnbye.com:3478",
];

/// 默认TCP STUN服务器（需要支持RFC5389/RFC8489）
const DEFAULT_TCP_STUN_SERVERS: &[&str] = &[
    "fwa.lifesizecloud.com:3478",
    "global.turn.twilio.com:3478",
    "turn.cloudflare.com:3478",
    "stun.voip.blackberry.com:3478",
    "stun.radiojar.com:3478",
];

/// NAT类型检测器
pub struct NatTypeDetector {
    udp_stun_servers: Vec<SocketAddr>,
    tcp_stun_servers: Vec<SocketAddr>,
}

impl NatTypeDetector {
    pub fn new(udp_stun_servers: Vec<SocketAddr>, tcp_stun_servers: Vec<SocketAddr>) -> Self {
        Self { udp_stun_servers, tcp_stun_servers }
    }

    /// 检测UDP NAT类型（基于natter的RFC3489方法）
    pub async fn detect_udp_nat_type(&self) -> Result<NatType, anyhow::Error> {
        if self.udp_stun_servers.len() < 2 {
            anyhow::bail!("need at least 2 udp stun servers");
        }

        let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let mut client_builder = StunClientBuilder::new(udp.clone());

        // 测试1：基本绑定请求，做两次
        let mut test1_results = vec![];
        for server in self.udp_stun_servers.iter().take(2) {
            let client = client_builder.new_stun_client(*server);
            let resp = client.bind_request(false, false).await?;
            test1_results.push(resp);
        }

        // 如果两次测试1的mapped地址不同 → Symmetric
        if test1_results[0].mapped_socket_addr != test1_results[1].mapped_socket_addr {
            client_builder.stop().await;
            return Ok(NatType::Symmetric);
        }

        // 测试2：change_ip=True, change_port=True
        // 使用与测试1第二个相同的STUN服务器
        let test2_server = self.udp_stun_servers[1];
        let test2_result = {
            let client = client_builder.new_stun_client(test2_server);
            client.bind_request(true, true).await
        };

        // 验证测试2的响应是否来自不同的IP和端口
        let test2_valid = if let Ok(ref resp) = test2_result {
            tracing::debug!(resp.real_ip_changed, resp.real_port_changed, "test2 response");
            resp.real_ip_changed && resp.real_port_changed
        } else {
            tracing::debug!(?test2_result, "test2 failed");
            false
        };

        // 测试3：change_ip=False, change_port=True
        let test3_result = {
            let client = client_builder.new_stun_client(test2_server);
            client.bind_request(false, true).await
        };

        client_builder.stop().await;

        let source_addr = test1_results[0].local_addr;
        let mapped_addr = test1_results[0].mapped_socket_addr.unwrap();

        // 如果源地址 == mapped地址（公网IP）
        if source_addr == mapped_addr {
            if test2_valid {
                return Ok(NatType::OpenInternet);
            } else {
                return Ok(NatType::SymUdpFirewall);
            }
        }

        // 有NAT
        if test2_valid {
            return Ok(NatType::FullCone);
        }

        // 不是FullCone，尝试UPnP
        println!("UDP NAT: Symmetric/Restricted，尝试UDP UPnP...");

        // 获取一个随机可用端口
        let upnp_port = self.get_free_port().await?;

        // 配置UDP UPnP映射
        match upnp::try_open_udp_port(upnp_port).await {
            Ok(Some(lease)) => {
                let external_port = lease.gateway_external_port();
                println!("UDP UPnP成功: {} -> {}", upnp_port, external_port);

                // 使用UPnP映射的端口重新测试
                let udp = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", upnp_port)).await?);
                let mut client_builder = StunClientBuilder::new(udp.clone());

                // 测试1：基本绑定请求
                let test1_result = {
                    let client = client_builder.new_stun_client(self.udp_stun_servers[0]);
                    client.bind_request(false, false).await
                };

                // 测试2：change_ip=True, change_port=True
                let test2_result = {
                    let client = client_builder.new_stun_client(self.udp_stun_servers[0]);
                    client.bind_request(true, true).await
                };

                client_builder.stop().await;

                if let Ok(resp) = test1_result {
                    let mapped_addr = resp.mapped_socket_addr.unwrap();
                    let public_port = mapped_addr.port();
                    println!("STUN外部端口: {}", public_port);

                    // 测试2成功说明是FullCone
                    if test2_result.is_ok() {
                        return Ok(NatType::FullCone);
                    }
                }
            }
            Ok(None) => {
                println!("UDP UPnP失败: 未找到网关");
            }
            Err(e) => {
                println!("UDP UPnP失败: {}", e);
            }
        }

        if test3_result.is_ok() {
            return Ok(NatType::Restricted);
        }

        Ok(NatType::PortRestricted)
    }

    /// 检测TCP NAT类型（基于natter的方法）
    pub async fn detect_tcp_nat_type(&self) -> Result<NatType, anyhow::Error> {
        if self.tcp_stun_servers.is_empty() {
            anyhow::bail!("need at least 1 tcp stun server");
        }

        tracing::debug!("detect_tcp_nat_type start");

        // 首先调用check_tcp_fullcone检测
        let fullcone_result = self.check_tcp_fullcone().await?;
        tracing::debug!(fullcone_result, "check_tcp_fullcone result");
        match fullcone_result {
            2 => return Ok(NatType::OpenInternet),
            1 => return Ok(NatType::FullCone),
            0 => return Ok(NatType::Unknown),
            _ => {}
        }

        // 不是FullCone，先检测是PortRestricted还是Symmetric
        let cone_result = self.check_tcp_cone().await?;
        let nat_type_name = match cone_result {
            1 => "PortRestricted",
            -1 => "Symmetric",
            _ => "Unknown",
        };
        println!("TCP NAT: {}，尝试TCP UPnP...", nat_type_name);

        // 获取一个随机可用端口
        let source_port = self.get_free_port().await?;
        tracing::debug!(source_port, "got free port for upnp");

        // 配置UPnP映射到该端口
        match upnp::try_open_tcp_port(source_port).await {
            Ok(Some(lease)) => {
                let external_port = lease.gateway_external_port();
                println!("TCP UPnP成功: {} -> {}", source_port, external_port);
                tracing::debug!(source_port, external_port, "upnp configured");

                // 先用STUN测试获取mapped地址（STUN连接保持活跃）
                let stun_result = {
                    let mut result = None;
                    for server in &self.tcp_stun_servers {
                        match self.tcp_test(*server, source_port).await {
                            Ok(r) => {
                                result = Some(r);
                                break;
                            }
                            Err(_) => continue,
                        }
                    }
                    result
                };

                let Some((_stun_stream, mapped_addr)) = stun_result else {
                    tracing::debug!("no available STUN server for upnp test");
                    return match cone_result {
                        1 => Ok(NatType::PortRestricted),
                        -1 => Ok(NatType::Symmetric),
                        _ => Ok(NatType::Unknown),
                    };
                };
                tracing::debug!(source_port, ?mapped_addr, "stun mapped addr with upnp port");

                // STUN连接关闭后端口可能处于TIME_WAIT，用SO_REUSEADDR绑定
                use socket2::{Domain, Protocol, Socket, Type};
                let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                sock.set_reuse_address(true)?;
                sock.bind(&socket2::SockAddr::from(format!("0.0.0.0:{}", source_port).parse::<SocketAddr>().unwrap()))?;
                sock.listen(1)?;
                let listener = tokio::net::TcpListener::from_std(sock.into())?;
                tracing::debug!(source_port, "tcp listener created");

                // 测试STUN返回的外部端口是否可达
                let public_port = mapped_addr.port();
                let port_reachable = self.check_port_reachable(public_port).await?;
                tracing::debug!(public_port, port_reachable, "stun port reachable result");

                drop(listener);

                if port_reachable {
                    return Ok(NatType::FullCone);
                }
            }
            Ok(None) => {
                println!("TCP UPnP失败: 未找到网关");
                tracing::debug!("upnp not available");
            }
            Err(e) => {
                println!("TCP UPnP失败: {}", e);
                tracing::debug!(?e, "upnp error");
            }
        }

        // 返回之前检测的结果
        match cone_result {
            1 => return Ok(NatType::PortRestricted),
            -1 => return Ok(NatType::Symmetric),
            _ => return Ok(NatType::Unknown),
        }
    }

    /// 检测TCP完全锥形NAT（基于natter的方法）
    async fn check_tcp_fullcone(&self) -> Result<i32, anyhow::Error> {
        // 获取空闲端口
        let source_port = self.get_free_port().await?;
        self.check_tcp_fullcone_with_port(source_port).await
    }

    /// 使用指定端口检测TCP完全锥形NAT
    async fn check_tcp_fullcone_with_port(&self, source_port: u16) -> Result<i32, anyhow::Error> {
        tracing::debug!(source_port, "check_tcp_fullcone_with_port start");

        // 使用STUN获取mapped地址，同时STUN连接保持活跃
        let (stream, mapped_addr) = {
            let mut result = None;
            for server in &self.tcp_stun_servers {
                match self.tcp_test(*server, source_port).await {
                    Ok(r) => {
                        result = Some(r);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            match result {
                Some(r) => r,
                None => anyhow::bail!("no available STUN server"),
            }
        };

        let source_addr = stream.local_addr()?;
        tracing::debug!(source_port, ?source_addr, ?mapped_addr, "got tcp mapping");

        // 检查是否是开放互联网
        if source_addr == mapped_addr {
            tracing::debug!(source_port, "open internet detected");
            return Ok(2);
        }

        // 检查公网端口是否可达
        let public_port = mapped_addr.port();
        tracing::debug!(source_port, public_port, "checking port reachable");
        let port_reachable = self.check_port_reachable(public_port).await?;
        tracing::debug!(source_port, public_port, port_reachable, "port reachable result");

        if port_reachable {
            tracing::debug!(source_port, "fullcone detected");
            Ok(1) // FullCone
        } else {
            tracing::debug!(source_port, "port restricted or symmetric");
            Ok(-1) // PortRestricted或Symmetric
        }
    }

    /// TCP STUN测试，返回stream保持连接活跃
    async fn tcp_test(&self, stun_host: SocketAddr, source_port: u16) -> Result<(tokio::net::TcpStream, SocketAddr), anyhow::Error> {
        use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};

        tracing::debug!(?stun_host, source_port, "tcp_test start");

        let socket = Socket::new(
            Domain::IPV4,
            Type::STREAM,
            Some(Protocol::TCP),
        )?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;

        // Windows上也需要设置reuse_port
        #[cfg(unix)]
        {
            let _ = socket.set_reuse_port(true);
        }

        let bind_addr = SocketAddr::new("0.0.0.0".parse()?, source_port);
        socket.bind(&SockAddr::from(bind_addr))?;
        tracing::debug!(source_port, "socket bound to port");

        let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
        let mut stream = socket.connect(stun_host).await?;
        tracing::debug!(?stun_host, source_port, "connected to stun server");

        // 设置linger选项为0，确保端口立即释放
        let _ = SockRef::from(&stream).set_linger(Some(std::time::Duration::ZERO));

        // 发送STUN绑定请求
        let tid = rand::random::<u128>();
        let mut transaction_id_bytes = [0u8; 12];
        transaction_id_bytes.copy_from_slice(&tid.to_be_bytes()[4..]);
        let transaction_id = TransactionId::new(transaction_id_bytes);

        let message: Message<Attribute> = Message::new(
            MessageClass::Request,
            stun_codec::rfc5389::methods::BINDING,
            transaction_id,
        );

        let mut encoder = MessageEncoder::new();
        let msg = encoder.encode_into_bytes(message)?;
        stream.write_all(&msg).await?;
        tracing::debug!(?stun_host, "sent stun request");

        // 读取响应
        let mut buf = [0u8; 1500];
        let n = stream.read(&mut buf).await?;
        tracing::debug!(?stun_host, n, "received stun response");

        let mut decoder = MessageDecoder::<Attribute>::new();
        let Ok(response) = decoder
            .decode_from_bytes(&buf[..n])
            .with_context(|| "decode stun message failed")?
        else {
            anyhow::bail!("decode stun message failed");
        };

        let source_addr = stream.local_addr()?;
        let mapped_addr = Self::extract_mapped_addr(&response);
        tracing::debug!(?stun_host, ?source_addr, ?mapped_addr, "tcp_test result");

        Ok((stream, mapped_addr))
    }

    fn extract_mapped_addr(msg: &Message<Attribute>) -> SocketAddr {
        for attr in msg.attributes() {
            match attr {
                Attribute::MappedAddress(addr) => return addr.address(),
                Attribute::XorMappedAddress(addr) => return addr.address(),
                _ => {}
            }
        }
        SocketAddr::new("0.0.0.0".parse().unwrap(), 0)
    }

    /// 检测TCP锥形NAT（基于natter的方法）
    async fn check_tcp_cone(&self) -> Result<i32, anyhow::Error> {
        let source_port = self.get_free_port().await?;
        let mut mapped_addr_first = None;
        let mut count = 0;

        for server in self.tcp_stun_servers.iter().take(3) {
            match self.tcp_test(*server, source_port).await {
                Ok((_stream, mapped_addr)) => {
                    if let Some(first) = mapped_addr_first {
                        if mapped_addr != first {
                            return Ok(-1); // Symmetric
                        }
                    } else {
                        mapped_addr_first = Some(mapped_addr);
                    }
                    count += 1;
                }
                Err(_) => continue,
            }
        }

        if count >= 3 {
            Ok(1) // PortRestricted
        } else {
            Ok(0) // Unknown
        }
    }

    /// 获取空闲端口
    async fn get_free_port(&self) -> Result<u16, anyhow::Error> {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        Ok(port)
    }

    /// 检查端口是否可达
    async fn check_port_reachable(&self, port: u16) -> Result<bool, anyhow::Error> {
        let url = format!("http://{}/{}", PORT_TEST_SERVER, port);
        tracing::debug!(port, url, "checking port reachable");
        let client = reqwest::Client::new();
        let resp = client.get(&url).timeout(Duration::from_secs(8)).send().await?;
        let body = resp.text().await?;
        let body = body.trim();
        tracing::debug!(port, body, "port check response");

        if body == "1" {
            Ok(true)
        } else if body == "0" {
            Ok(false)
        } else {
            anyhow::bail!("unexpected response: {}", body)
        }
    }
}
