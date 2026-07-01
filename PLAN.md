# NAT Type 检测工具移植计划

## 1. 项目概述

将EasyTier的NAT检测代码移植为独立的Rust命令行工具，专注于区分三种NAT类型：
- **3 = FullCone** (完全锥形NAT)
- **5 = PortRestricted** (端口受限锥形NAT)
- **6 = Symmetric** (对称NAT)

## 2. 需要移植的文件

### 2.1 从EasyTier移植的核心文件

| 文件 | 说明 | 修改程度 |
|------|------|----------|
| `easytier/src/common/stun.rs` | STUN客户端和NAT检测逻辑 | 需要移除EasyTier特定依赖 |
| `easytier/src/common/stun_codec_ext.rs` | STUN编解码扩展 | 无需修改 |
| `easytier/src/proto/common.proto` | NatType枚举定义 | 需要提取NatType枚举 |

### 2.2 依赖项

从EasyTier的Cargo.toml中需要的依赖：
```toml
stun_codec = "0.3.4"
bytecodec = "0.4.15"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
```

## 3. 需要修改的部分

### 3.1 移除EasyTier特定依赖

- `crate::proto::common::{NatType, StunInfo}` → 将NatType枚举定义在本地
- `crate::common::error::Error` → 使用anyhow::Error替代
- `super::dns::resolve_txt_record` → 实现简化的DNS解析
- `chrono`, `crossbeam`, `quanta`, `rand`, `socket2` → 评估是否需要保留

### 3.2 检测逻辑（基于natter的方法）

专注于区分三种NAT类型：

**natter的TCP NAT检测流程**：
1. 使用STUN服务器获取mapped地址（公网IP:端口）
2. 使用`portcheck.transmissionbt.com`测试公网端口是否可达
3. 如果端口可达 → FullCone (1)
4. 如果端口不可达 → 再通过多个STUN服务器判断是PortRestricted还是Symmetric

**natter的UDP NAT检测流程**（RFC3489）：
1. 测试1：基本绑定请求，做两次
2. 测试2：change_ip=True, change_port=True
3. 测试3：change_ip=False, change_port=True

**集成方案**：
- 保留EasyTier的STUN客户端代码（stun_codec库）
- 实现natter的端口可达性测试（使用portcheck.transmissionbt.com）
- 结合两种方法区分FullCone、PortRestricted、Symmetric

## 4. 实现步骤

### 步骤1：创建项目结构
```powershell
mkdir d:\nattype
cd d:\nattype
cargo init --name nattype
```

### 步骤2：配置Cargo.toml
```toml
[package]
name = "nattype"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "nattype"
path = "src/main.rs"

[dependencies]
stun_codec = "0.3.4"
bytecodec = "0.4.15"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
```

### 步骤3：移植核心代码
1. 复制`stun_codec_ext.rs`到`src/stun_codec_ext.rs`
2. 创建`src/nat_type.rs`，定义NatType枚举
3. 创建`src/stun.rs`，移植STUN客户端代码
4. 创建`src/detector.rs`，实现NAT检测逻辑

### 步骤4：实现命令行接口
```rust
// src/main.rs
use clap::Parser;

#[derive(Parser)]
struct Cli {
    /// STUN server addresses
    #[arg(short, long)]
    servers: Option<Vec<String>>,
    
    /// Source port
    #[arg(short, long, default_value = "0")]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // 执行NAT检测
    // 输出结果
    Ok(())
}
```

### 步骤5：编译和测试
```powershell
cargo build --release
.\target\release\nattype.exe
```

## 5. NAT类型输出格式

支持三种类型：
```
NAT Type: FullCone (3)
```
或
```
NAT Type: PortRestricted (5)
```
或
```
NAT Type: Symmetric (6)
```

## 6. 与EasyTier的一致性保证

1. **代码结构**：保持与EasyTier相同的模块划分
2. **类型定义**：使用相同的NatType枚举
3. **检测逻辑**：保留EasyTier的核心检测算法
4. **依赖管理**：使用相同的stun_codec版本

## 7. 风险和注意事项

1. **DNS解析**：EasyTier使用自定义的DNS解析（txt:stun.easytier.cn），需要实现或简化
2. **异步运行时**：确保tokio版本兼容
3. **错误处理**：使用anyhow替代EasyTier的自定义Error类型
4. **测试覆盖**：需要在不同网络环境下测试

## 8. 时间估算

- 步骤1-2：5分钟
- 步骤3：20分钟（简化了检测逻辑）
- 步骤4：10分钟
- 步骤5：10分钟
- 总计：约45分钟
