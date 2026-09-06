//! Print the Wasabi wallet file for the SLIP-0019 test seed ("all all ...").
//! `cargo run -p wallet-rpc-core --example wasabi_wallet > test-wallet.json`
use wallet_rpc_core::coinjoin::Policy;
use wallet_rpc_core::ngwallet::bdk_wallet::bitcoin::Network;
use wallet_rpc_core::ngwallet::bdk_wallet::keys::bip39::Mnemonic;
use wallet_rpc_core::protocol::{Backend, Engine};
use wallet_rpc_core::zeroize::Zeroizing;

struct TestSeed;
impl Backend for TestSeed {
    fn firmware_version(&self) -> String { "example".into() }
    fn seed(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let m = Mnemonic::parse("all all all all all all all all all all all all").unwrap();
        Some(Zeroizing::new(m.to_seed("").to_vec()))
    }
    fn approve_policy(&mut self, _: &Policy) -> bool { true }
    fn random_bytes(&mut self, out: &mut [u8]) -> bool { out.fill(7); true }
}

fn main() {
    const H: u32 = 0x8000_0000;
    let mut engine = Engine::new(TestSeed);
    let (fp, x84) = engine.xpub(Network::Bitcoin, &[84 | H, H, H]).unwrap();
    let (_, x86) = engine.xpub(Network::Bitcoin, &[86 | H, H, H]).unwrap();
    print!("{}", wallet_rpc_core::wasabi::wallet_json(&fp.to_string(), &x84, &x86));
}
