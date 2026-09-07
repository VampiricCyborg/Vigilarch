//! # vigil-node
//!
//! A single process that exposes one in-memory [`vigil_ledger`] store over a
//! loopback HTTP API: capture a record, read its provenance, export an evidence
//! pack, check liveness. It is **not** a multi-node system — see the library
//! docs (`vigil_node`) for why the `edge|hub|mule` role distinction is not here.
//!
//! ## Why a synchronous HTTP server (`tiny_http`), not `axum`
//!
//! The workspace's async runtime is `tokio`, and `axum` would be the idiomatic
//! pairing. This crate uses the synchronous `tiny_http` instead, deliberately:
//!
//! - The surface is four loopback endpoints over an in-memory store. Every
//!   handler is a lock plus a few microseconds of CPU; there is nothing to
//!   `.await` and no benefit from an async runtime.
//! - `tiny_http` pulls ~4 small crates. `axum` pulls the `hyper`/`tower` tree —
//!   dozens of crates — for no capability this scope uses. `CLAUDE.md` is
//!   explicit that dependency weight trades against the project's goals.
//! - A blocking handler over a `Mutex<MemoryStore>` is easier to read and to
//!   verify against the "capture never blocks" invariant than the same logic
//!   threaded through `async fn` and `Send` bounds.
//!
//! If real network sync arrives in v2 and the node needs streaming peer
//! connections, revisit this — that is the point where an async server earns
//! its dependencies.
//!
//! ```text
//! cargo run -p vigil-node -- --addr 127.0.0.1:8787
//! curl -s -XPOST --data 'grid B4 shoring is out of plumb' localhost:8787/obs
//! curl -s localhost:8787/obs/<id>/provenance
//! curl -s -XPOST --data '["<id>"]' localhost:8787/export -o pack.bin
//! ```

use std::process::ExitCode;

use vigil_node::{Node, serve, shared};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match Config::parse(&args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!(
                "usage: vigil-node [--addr <ip:port>] [--role edge|hub|mule]\n  \
                 --addr   loopback address to bind (default 127.0.0.1:8787)\n  \
                 --role   accepted for forward-compatibility; has no effect in v1"
            );
            return ExitCode::from(2);
        }
    };

    if let Some(role) = &config.role {
        // Accepted, not acted on. The role only means something once vigil-sync
        // exists (v2): edge/hub/mule differ in sync policy and nothing else, and
        // there is no sync here. Branching on it now would be dead code.
        eprintln!("vigil-node: --role {role} accepted but has no effect in v1 (no sync layer)");
    }

    let node = match Node::new() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("vigil-node: could not initialise: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    let pubkey = node.pubkey();

    let server = match tiny_http::Server::http(config.addr.as_str()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vigil-node: could not bind {}: {e}", config.addr);
            return ExitCode::FAILURE;
        }
    };

    eprintln!("vigil-node listening on http://{}", config.addr);
    eprintln!("node key: {pubkey}");
    eprintln!("  (use this as <org-pubkey> for `vigil-verify <pack> <org-pubkey>`)");

    serve(shared(node), server);
    ExitCode::SUCCESS
}

struct Config {
    addr: String,
    role: Option<String>,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut addr = "127.0.0.1:8787".to_owned();
        let mut role = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--addr" => {
                    addr = it.next().ok_or("--addr needs a value")?.clone();
                }
                "--role" => {
                    let r = it.next().ok_or("--role needs a value")?.clone();
                    if !matches!(r.as_str(), "edge" | "hub" | "mule") {
                        return Err(format!("--role must be edge, hub, or mule (got {r})"));
                    }
                    role = Some(r);
                }
                other => return Err(format!("unexpected argument: {other}")),
            }
        }
        Ok(Self { addr, role })
    }
}
