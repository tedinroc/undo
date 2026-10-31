//! Dry-runs an escape from a recovery file and broadcasts nothing.
//!
//!     recovery-dry-run <file>
//!
//! Prints no secret. Exit 0 if the file can escape, 1 if it cannot, 2 on bad usage.

use undo_btc::recovery::dry_run_escape;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, path] = args.as_slice() else {
        eprintln!("usage: recovery-dry-run <file>");
        std::process::exit(2);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => {
            println!("FAIL C18 [consensus-lib] could not read the file");
            std::process::exit(1);
        }
    };
    match dry_run_escape(&text) {
        Ok(r) => {
            println!(
                "PASS C18 [consensus-lib] recovery file escapes on a made-up coin: network {} csv {} script {} bytes tx {} vB",
                r.network.name(),
                r.csv,
                r.script_len,
                r.vsize
            );
            println!("PASS C18 [consensus-lib] controls refused: same key one block below csv, other key at csv");
            println!("NOT CHECKED: coin existence, coin age (BIP-68), relay policy. Those need a node.");
        }
        Err(e) => {
            println!("FAIL C18 [consensus-lib] {e}");
            std::process::exit(1);
        }
    }
}
