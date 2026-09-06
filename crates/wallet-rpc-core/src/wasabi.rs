//! Wasabi Wallet import file for the signer's wallet (watch-only, PSBT workflow).

/// Wasabi wallet file for the app-seed wallet: watch-only, both account xpubs,
/// PSBT workflow. The shape is what `KeyManager.FromFile` decodes (ExtPubKey and
/// BlockchainState are the only required fields); MasterFingerprint is the
/// BIP-32 fingerprint in its usual hex order.
pub fn wallet_json(fingerprint: &str, xpub84: &str, xpub86: &str) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"MasterFingerprint\": \"{fp}\",\n",
            "  \"ExtPubKey\": \"{x84}\",\n",
            "  \"TaprootExtPubKey\": \"{x86}\",\n",
            "  \"MinGapLimit\": 21,\n",
            "  \"AccountKeyPath\": \"84'/0'/0'\",\n",
            "  \"TaprootAccountKeyPath\": \"86'/0'/0'\",\n",
            "  \"BlockchainState\": {{ \"Network\": \"Main\", \"Height\": 0 }},\n",
            "  \"PreferPsbtWorkflow\": true,\n",
            "  \"AutoCoinJoin\": true,\n",
            "  \"HdPubKeys\": []\n",
            "}}\n"
        ),
        fp = fingerprint,
        x84 = xpub84,
        x86 = xpub86,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn wallet_json_has_the_fields_wasabi_requires() {
        let json = super::wallet_json("5c9e228d", "xpub6A", "xpub6B");
        // KeyManager.FromFile: ExtPubKey and BlockchainState are required.
        for key in ["\"ExtPubKey\": \"xpub6A\"", "\"TaprootExtPubKey\": \"xpub6B\"",
                    "\"MasterFingerprint\": \"5c9e228d\"", "\"BlockchainState\"", "\"Network\": \"Main\""] {
            assert!(json.contains(key), "missing {key}");
        }
        assert_eq!(json.matches('{').count(), json.matches('}').count());
    }
}
