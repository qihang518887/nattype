/// NAT类型枚举，与EasyTier的NatType保持一致
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// 未知
    Unknown = 0,
    /// 开放互联网
    OpenInternet = 1,
    /// 无PAT（端口未转换）
    NoPat = 2,
    /// 完全锥形NAT
    FullCone = 3,
    /// 受限锥形NAT
    Restricted = 4,
    /// 端口受限锥形NAT
    PortRestricted = 5,
    /// 对称NAT
    Symmetric = 6,
    /// 对称UDP防火墙
    SymUdpFirewall = 7,
    /// 对称NAT（端口递增）
    SymmetricEasyInc = 8,
    /// 对称NAT（端口递减）
    SymmetricEasyDec = 9,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Unknown => write!(f, "Unknown"),
            NatType::OpenInternet => write!(f, "OpenInternet"),
            NatType::NoPat => write!(f, "NoPat"),
            NatType::FullCone => write!(f, "FullCone"),
            NatType::Restricted => write!(f, "Restricted"),
            NatType::PortRestricted => write!(f, "PortRestricted"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::SymUdpFirewall => write!(f, "SymUdpFirewall"),
            NatType::SymmetricEasyInc => write!(f, "SymmetricEasyInc"),
            NatType::SymmetricEasyDec => write!(f, "SymmetricEasyDec"),
        }
    }
}
