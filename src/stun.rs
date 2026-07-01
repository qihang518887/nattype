use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinSet;
use tracing::Instrument;

use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};

use crate::stun_codec_ext::*;

/// 默认UDP STUN服务器
const DEFAULT_UDP_STUN_SERVERS: &[&str] = &[
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
    "stun.cdnbye.com",
];

/// 默认TCP STUN服务器
const DEFAULT_TCP_STUN_SERVERS: &[&str] = &[
    "fwa.lifesizecloud.com",
    "global.turn.twilio.com",
    "turn.cloudflare.com",
    "stun.voip.blackberry.com",
    "stun.radiojar.com",
];

/// STUN数据包
#[derive(Debug, Clone)]
struct StunPacket {
    data: Vec<u8>,
    addr: SocketAddr,
}

type StunPacketReceiver = tokio::sync::broadcast::Receiver<StunPacket>;

/// 绑定请求响应
#[derive(Debug, Clone, Copy)]
pub struct BindRequestResponse {
    pub local_addr: SocketAddr,
    pub stun_server_addr: SocketAddr,
    pub recv_from_addr: SocketAddr,
    pub mapped_socket_addr: Option<SocketAddr>,
    pub changed_socket_addr: Option<SocketAddr>,
    pub change_ip: bool,
    pub change_port: bool,
    pub real_ip_changed: bool,
    pub real_port_changed: bool,
    pub latency_us: u32,
}

/// STUN客户端
#[derive(Debug, Clone)]
pub struct StunClient {
    stun_server: SocketAddr,
    resp_timeout: Duration,
    req_repeat: u32,
    socket: Arc<UdpSocket>,
    stun_packet_receiver: Arc<Mutex<StunPacketReceiver>>,
}

impl StunClient {
    pub fn new(
        stun_server: SocketAddr,
        socket: Arc<UdpSocket>,
        stun_packet_receiver: StunPacketReceiver,
    ) -> Self {
        Self {
            stun_server,
            resp_timeout: Duration::from_millis(3000),
            req_repeat: 2,
            socket,
            stun_packet_receiver: Arc::new(Mutex::new(stun_packet_receiver)),
        }
    }

    async fn wait_stun_response<'a, const N: usize>(
        &self,
        buf: &'a mut [u8; N],
        tids: &Vec<u32>,
        expected_ip_changed: bool,
        expected_port_changed: bool,
        stun_host: &SocketAddr,
    ) -> Result<(Message<Attribute>, SocketAddr), anyhow::Error> {
        let mut now = tokio::time::Instant::now();
        let deadline = now + self.resp_timeout;

        while now < deadline {
            let mut locked_receiver = self.stun_packet_receiver.lock().await;
            let stun_packet_raw = tokio::time::timeout(deadline - now, locked_receiver.recv())
                .await
                .unwrap_or(Err(broadcast::error::RecvError::Closed));

            match stun_packet_raw {
                Ok(stun_packet) => {
                    let recv_addr = stun_packet.addr;
                    let data = stun_packet.data;
                    let expected_recv_from_ip_changed = stun_host.ip() != recv_addr.ip();
                    let expected_recv_from_port_changed = stun_host.port() != recv_addr.port();

                    if expected_recv_from_ip_changed != expected_ip_changed
                        || expected_recv_from_port_changed != expected_port_changed
                    {
                        continue;
                    }

                    buf[..data.len()].copy_from_slice(data.as_slice());

                    let mut decoder = MessageDecoder::<Attribute>::new();
                    let msg = match decoder.decode_from_bytes(&buf[..data.len()]) {
                        Ok(Ok(msg)) => msg,
                        Ok(Err(e)) => {
                            tracing::warn!(?e, "decode stun message failed");
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(?e, "decode stun message failed");
                            continue;
                        }
                    };

                    let method = BINDING;
                    if msg.class() != MessageClass::SuccessResponse || msg.method() != method {
                        continue;
                    }

                    let tid = tid_to_u32(&msg.transaction_id());
                    if !tids.contains(&tid) {
                        continue;
                    }

                    return Ok((msg, recv_addr));
                }
                Err(e) => {
                    tracing::warn!(?e, "receive stun packet failed");
                    break;
                }
            }
        }

        anyhow::bail!("stun response timeout")
    }

    pub async fn bind_request(
        &self,
        change_ip: bool,
        change_port: bool,
    ) -> Result<BindRequestResponse, anyhow::Error> {
        let mut tids = vec![];
        let stun_host = self.stun_server;
        let method = BINDING;

        for _ in 0..self.req_repeat {
            let tid = rand::random::<u32>();
            tids.push(tid);
            let transaction_id = u32_to_tid(tid);
            let mut message: Message<Attribute> = Message::new(MessageClass::Request, method, transaction_id);

            message.add_attribute(Attribute::ChangeRequest(ChangeRequest::new(change_ip, change_port)));

            let mut encoder = MessageEncoder::new();
            let msg = encoder
                .encode_into_bytes(message.clone())
                .with_context(|| "encode stun message")?;
            self.socket.send_to(msg.as_slice(), &stun_host).await?;
        }

        let mut buf = [0; 1620];
        let (msg, recv_addr) = self
            .wait_stun_response(&mut buf, &tids, change_ip, change_port, &stun_host)
            .await?;

        let changed_socket_addr = Self::extract_changed_addr(&msg);
        let real_ip_changed = stun_host.ip() != recv_addr.ip();
        let real_port_changed = stun_host.port() != recv_addr.port();

        let resp = BindRequestResponse {
            local_addr: self.socket.local_addr()?,
            stun_server_addr: stun_host,
            recv_from_addr: recv_addr,
            mapped_socket_addr: Self::extract_mapped_addr(&msg),
            changed_socket_addr,
            change_ip,
            change_port,
            real_ip_changed,
            real_port_changed,
            latency_us: 0,
        };

        Ok(resp)
    }

    fn extract_mapped_addr(msg: &Message<Attribute>) -> Option<SocketAddr> {
        for attr in msg.attributes() {
            match attr {
                Attribute::MappedAddress(addr) => return Some(addr.address()),
                Attribute::XorMappedAddress(addr) => return Some(addr.address()),
                _ => {}
            }
        }
        None
    }

    fn extract_changed_addr(msg: &Message<Attribute>) -> Option<SocketAddr> {
        for attr in msg.attributes() {
            match attr {
                Attribute::ChangedAddress(addr) => return Some(addr.address()),
                _ => {}
            }
        }
        None
    }
}

/// STUN客户端构建器
pub struct StunClientBuilder {
    udp: Arc<UdpSocket>,
    task_set: JoinSet<()>,
    stun_packet_sender: broadcast::Sender<StunPacket>,
}

impl StunClientBuilder {
    pub fn new(udp: Arc<UdpSocket>) -> Self {
        let (stun_packet_sender, _) = broadcast::channel(1024);
        let mut task_set = JoinSet::new();

        let udp_clone = udp.clone();
        let stun_packet_sender_clone = stun_packet_sender.clone();
        task_set.spawn(
            async move {
                let mut buf = [0; 1620];
                tracing::trace!("start stun packet listener");
                loop {
                    let Ok((len, addr)) = udp_clone.recv_from(&mut buf).await else {
                        tracing::error!("udp recv_from error");
                        break;
                    };
                    let data = buf[..len].to_vec();
                    tracing::trace!(?addr, ?data, "recv udp stun packet");
                    let _ = stun_packet_sender_clone.send(StunPacket { data, addr });
                }
            }
            .instrument(tracing::info_span!("stun_packet_listener")),
        );

        Self {
            udp,
            task_set,
            stun_packet_sender,
        }
    }

    pub fn new_stun_client(&self, stun_server: SocketAddr) -> StunClient {
        StunClient::new(
            stun_server,
            self.udp.clone(),
            self.stun_packet_sender.subscribe(),
        )
    }

    pub async fn stop(&mut self) {
        self.task_set.abort_all();
        while self.task_set.join_next().await.is_some() {}
    }
}

/// 解析STUN服务器地址
pub async fn resolve_stun_servers(servers: &[&str]) -> Vec<SocketAddr> {
    let mut result = vec![];
    for server in servers {
        if let Ok(addrs) = tokio::net::lookup_host(server).await {
            for addr in addrs {
                if addr.is_ipv4() {
                    result.push(addr);
                }
            }
        }
    }
    result
}
