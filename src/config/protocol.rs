use serde::Deserialize;
use std::collections::HashSet;

/// Protocol feature flags that control which groups of detectors are enabled.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    pub uses_fot_tokens: bool,
    pub uses_weird_erc20: bool,
    pub uses_native_token: bool,
    pub uses_l2: bool,
    pub uses_nft: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            uses_fot_tokens: true,
            uses_weird_erc20: true,
            uses_native_token: true,
            uses_l2: true,
            uses_nft: true,
        }
    }
}

pub const FOT_TOKEN_DETECTORS: &[&str] = &["fee-on-transfer"];

pub const WEIRD_ERC20_DETECTORS: &[&str] = &["zero-value-transfer", "large-approval"];

pub const NATIVE_TOKEN_DETECTORS: &[&str] = &["empty-ether-receiver"];

pub const L2_DETECTORS: &[&str] = &["block-number-l2", "l2-sequencer-check"];

pub const NFT_DETECTORS: &[&str] = &["nft-mint-asymmetry", "nft-hard-fork", "use-erc721a"];

impl ProtocolConfig {
    pub fn get_excluded_detectors(&self) -> HashSet<String> {
        let mut excluded = HashSet::new();

        if !self.uses_fot_tokens {
            excluded.extend(FOT_TOKEN_DETECTORS.iter().map(|s| s.to_string()));
        }
        if !self.uses_weird_erc20 {
            excluded.extend(WEIRD_ERC20_DETECTORS.iter().map(|s| s.to_string()));
        }
        if !self.uses_native_token {
            excluded.extend(NATIVE_TOKEN_DETECTORS.iter().map(|s| s.to_string()));
        }
        if !self.uses_l2 {
            excluded.extend(L2_DETECTORS.iter().map(|s| s.to_string()));
        }
        if !self.uses_nft {
            excluded.extend(NFT_DETECTORS.iter().map(|s| s.to_string()));
        }

        excluded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_excludes_nothing() {
        let config = ProtocolConfig::default();
        let excluded = config.get_excluded_detectors();

        // All features are true by default, so nothing is excluded
        assert!(excluded.is_empty());
    }

    #[test]
    fn test_disabled_feature_excluded() {
        let config = ProtocolConfig {
            uses_fot_tokens: false,
            ..Default::default()
        };
        let excluded = config.get_excluded_detectors();

        // FoT detectors should be excluded
        assert!(excluded.contains("fee-on-transfer"));

        // Other detectors should NOT be excluded
        assert!(!excluded.contains("block-number-l2"));
    }
}
