mod nat_type;
mod stun;
mod stun_codec_ext;
mod detector;
mod upnp;

use std::net::SocketAddr;

use clap::Parser;

/// NAT类型检测工具
#[derive(Parser)]
#[command(name = "nattype")]
#[command(about = "检测NAT类型")]
struct Cli {
    /// UDP STUN服务器地址（可多个）
    #[arg(long)]
    udp_servers: Vec<String>,

    /// TCP STUN服务器地址（可多个）
    #[arg(long)]
    tcp_servers: Vec<String>,

    /// 检测TCP NAT类型
    #[arg(long)]
    tcp: bool,

    /// 检测UDP NAT类型
    #[arg(long)]
    udp: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志，默认info级别
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // 如果没有指定TCP或UDP，默认都检测
    let detect_tcp = cli.tcp || (!cli.tcp && !cli.udp);
    let detect_udp = cli.udp || (!cli.tcp && !cli.udp);

    // 解析UDP STUN服务器地址
    let udp_stun_servers = if cli.udp_servers.is_empty() {
        // 使用默认UDP服务器
        stun::resolve_stun_servers(&[
            "stun.miwifi.com:3478",
            "stun.chat.bilibili.com:3478",
            "stun.hitv.com:3478",
            "stun.cdnbye.com:3478",
        ])
        .await
    } else {
        let mut servers = vec![];
        for server in &cli.udp_servers {
            if let Ok(addr) = server.parse::<SocketAddr>() {
                servers.push(addr);
            } else {
                // 尝试解析域名
                let resolved = stun::resolve_stun_servers(&[server]).await;
                servers.extend(resolved);
            }
        }
        servers
    };

    // 解析TCP STUN服务器地址
    let tcp_stun_servers = if cli.tcp_servers.is_empty() {
        // 使用默认TCP服务器
        stun::resolve_stun_servers(&[
            "fwa.lifesizecloud.com:3478",
            "global.turn.twilio.com:3478",
            "turn.cloudflare.com:3478",
            "stun.voip.blackberry.com:3478",
            "stun.radiojar.com:3478",
        ])
        .await
    } else {
        let mut servers = vec![];
        for server in &cli.tcp_servers {
            if let Ok(addr) = server.parse::<SocketAddr>() {
                servers.push(addr);
            } else {
                // 尝试解析域名
                let resolved = stun::resolve_stun_servers(&[server]).await;
                servers.extend(resolved);
            }
        }
        servers
    };

    if udp_stun_servers.is_empty() && tcp_stun_servers.is_empty() {
        eprintln!("错误：没有可用的STUN服务器");
        std::process::exit(1);
    }

    let detector = detector::NatTypeDetector::new(udp_stun_servers, tcp_stun_servers);

    if detect_udp {
        match detector.detect_udp_nat_type().await {
            Ok(nat_type) => {
                println!("UDP NAT Type: {} ({})", nat_type, nat_type as u8);
            }
            Err(e) => {
                eprintln!("UDP NAT检测失败: {}", e);
            }
        }
    }

    if detect_tcp {
        match detector.detect_tcp_nat_type().await {
            Ok(nat_type) => {
                println!("TCP NAT Type: {} ({})", nat_type, nat_type as u8);
            }
            Err(e) => {
                eprintln!("TCP NAT检测失败: {}", e);
            }
        }
    }

    Ok(())
}
