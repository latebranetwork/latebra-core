//! Live watcher demo (needs the `node` feature and a running latebrad).
//!
//!   cargo run -p lat-bridge --features node --example watch -- \
//!       127.0.0.1:4040 <htlc_id_hex> <hashlock_hex> [expiry]
//!
//! Prints one observation of the Latebra HTLC leg: Pending while open,
//! Revealed(<preimage>) once claimed (recovered by scanning mined blocks),
//! or RefundReady if it expired / vanished.

use lat_bridge::watcher::node::NodeObserver;
use lat_bridge::{PreimageWatch, WatchResult};

fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: watch <node_addr> <htlc_id_hex> <hashlock_hex> [expiry]");
        std::process::exit(2);
    }
    let addr = args[1].clone();
    let id = h32(&args[2]);
    let hashlock = h32(&args[3]);
    let expiry: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);

    let obs = NodeObserver::new(addr);
    let watch = PreimageWatch::new(id, hashlock, expiry);
    match watch.poll(&obs) {
        WatchResult::Pending => println!("PENDING — lock open, secret not yet revealed"),
        WatchResult::Revealed(pre) => println!("REVEALED preimage={}", hex::encode(pre)),
        WatchResult::RefundReady => println!("REFUND-READY — expired or vanished unclaimed"),
        WatchResult::BadPreimage => println!("BAD-PREIMAGE — claim did not match the hashlock"),
    }
}
