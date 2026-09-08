//! End-to-end tests over the real loopback server: start a node, drive it with
//! raw HTTP/1.1 on an ephemeral port, and assert the responses.
//!
//! The single-node honesty check runs through here: a node with no peer has no
//! attestation, so every record it holds is `unwitnessed` with the window open
//! above to the verification moment. That is asserted, not worked around.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use vigil_node::{Node, dispatch, serve, shared};

/// Start a server on `127.0.0.1:0` backed by a seeded node, and return its
/// address. The server thread runs until the test process exits.
fn start() -> SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind loopback");
    let addr = server.server_addr().to_ip().expect("an ip listen address");
    let node = shared(Node::from_seed([7u8; 32]));
    std::thread::spawn(move || serve(node, server));
    addr
}

/// One HTTP/1.1 request over a fresh connection. Returns
/// `(status, content_type, body)`.
fn http(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header/body separator");
    let headers = String::from_utf8_lossy(&raw[..sep]).to_lowercase();
    let resp_body = raw[sep + 4..].to_vec();

    let status: u16 = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("a status line");
    let content_type = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-type: "))
        .unwrap_or("")
        .to_owned();

    (status, content_type, resp_body)
}

fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).expect("response body is JSON")
}

#[test]
fn health_reports_the_node_is_up_with_its_key() {
    let addr = start();
    let (status, ctype, body) = http(addr, "GET", "/health", b"");
    assert_eq!(status, 200);
    assert!(ctype.starts_with("application/json"), "ctype was {ctype:?}");
    let v = json(&body);
    assert_eq!(v["status"], "ok");
    assert_eq!(v["chain_len"], 0);
    assert_eq!(
        v["node_pubkey"].as_str().unwrap().len(),
        64,
        "pubkey is 64 hex chars"
    );
}

#[test]
fn capture_then_provenance_reports_unwitnessed_for_a_lone_node() {
    let addr = start();

    // 1. capture
    let (status, _, body) = http(addr, "POST", "/obs", b"grid B4 shoring is out of plumb");
    assert_eq!(status, 201, "capture returns 201 Created");
    let captured = json(&body);
    let id = captured["id"].as_str().expect("an id").to_owned();
    assert_eq!(captured["seq"], 0, "first record is seq 0");
    assert_eq!(id.len(), 64);

    // 2. provenance of that record
    let (status, ctype, body) = http(addr, "GET", &format!("/obs/{id}/provenance"), b"");
    assert_eq!(status, 200);
    assert!(ctype.starts_with("application/json"));
    let p = json(&body);

    assert_eq!(p["observation"], id);
    assert_eq!(p["seq"], 0);
    // The node holds its own complete chain from genesis.
    assert_eq!(p["chain_verification"], "verified");

    // The core assertion: a lone node seals nothing.
    assert_eq!(p["sealed"], false, "no attestation exists → not sealed");
    assert_eq!(p["witness_depth"], 0);
    assert!(p["upper_bound"].is_null(), "no sealing attestation");
    assert!(p["lower_bound"].is_null());
    assert_eq!(
        p["unwitnessed_window"]["upper"], "verification-moment",
        "open above to the verification moment (spec/03 §5 step 6)"
    );
    assert_eq!(
        p["unwitnessed_window"]["lower"], "genesis",
        "open below to genesis — the node's own chain starts at seq 0"
    );
    assert_eq!(p["disputed"], false);
}

#[test]
fn a_second_capture_links_onto_the_first() {
    let addr = start();
    let (_, _, b0) = http(addr, "POST", "/obs", b"first");
    let (_, _, b1) = http(addr, "POST", "/obs", b"second");
    assert_eq!(json(&b0)["seq"], 0);
    assert_eq!(json(&b1)["seq"], 1);

    let (status, _, hb) = http(addr, "GET", "/health", b"");
    assert_eq!(status, 200);
    assert_eq!(json(&hb)["chain_len"], 2);
}

#[test]
fn export_returns_bytes_that_parse_as_a_valid_pack() {
    let addr = start();

    let (_, _, cap) = http(addr, "POST", "/obs", b"tag-out re-checked, crew clear");
    let id = json(&cap)["id"].as_str().unwrap().to_owned();

    let req = serde_json::to_vec(&vec![&id]).unwrap();
    let (status, ctype, pack) = http(addr, "POST", "/export", &req);
    assert_eq!(status, 200);
    assert_eq!(ctype, "application/octet-stream");

    // spec/03 §2.1 envelope check: the file marker, then a decodable envelope.
    assert!(
        pack.starts_with(vigil_ledger::PACK_MARKER),
        "pack begins with the vigilarch/1/pack marker"
    );
    let contents = vigil_ledger::parse_pack(&pack).expect("pack parses per spec/03 §5 steps 1-3");
    assert_eq!(contents.wire_version, 1);
    assert_eq!(
        contents.invalid_object_count, 0,
        "every carried object self-checks"
    );

    let want = {
        let raw = hex::decode(&id).unwrap();
        vigil_core::Hash(raw.try_into().unwrap())
    };
    assert!(
        contents.claims.contains(&want),
        "the claimed id is in the pack"
    );

    // The pack is issued under the node's own key; vigil-verify would be called
    // with that key. Confirm it round-trips as the org label.
    let (_, _, hb) = http(addr, "GET", "/health", b"");
    let node_key = json(&hb)["node_pubkey"].as_str().unwrap().to_owned();
    assert_eq!(hex::encode(contents.org.as_bytes()), node_key);
}

#[test]
fn export_rejects_a_claim_the_node_does_not_hold() {
    let addr = start();
    let bogus = "0".repeat(64);
    let req = serde_json::to_vec(&vec![&bogus]).unwrap();
    let (status, _, body) = http(addr, "POST", "/export", &req);
    assert_eq!(status, 400);
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .contains("does not hold"),
        "the error names the missing claim"
    );
}

#[test]
fn malformed_requests_get_the_right_status() {
    let addr = start();

    // empty capture body
    let (status, _, _) = http(addr, "POST", "/obs", b"");
    assert_eq!(status, 400);

    // provenance of a non-hex id
    let (status, _, _) = http(addr, "GET", "/obs/not-a-hash/provenance", b"");
    assert_eq!(status, 400);

    // provenance of a well-formed but unknown id
    let (status, _, _) = http(
        addr,
        "GET",
        &format!("/obs/{}/provenance", "a".repeat(64)),
        b"",
    );
    assert_eq!(status, 404);

    // wrong method on a real path
    let (status, _, _) = http(addr, "DELETE", "/obs", b"");
    assert_eq!(status, 405);

    // unknown path
    let (status, _, _) = http(addr, "GET", "/nope", b"");
    assert_eq!(status, 404);
}

/// The pure router, exercised without a socket.
#[test]
fn dispatch_routes_without_a_server() {
    let node = Node::from_seed([9u8; 32]);

    let r = dispatch(&node, "POST", "/obs", b"hello");
    assert_eq!(r.status, 201);

    let r = dispatch(&node, "GET", "/health", b"");
    assert_eq!(r.status, 200);
    assert_eq!(r.content_type, "application/json");

    let r = dispatch(&node, "GET", "/obs", b"");
    assert_eq!(r.status, 405);

    let r = dispatch(&node, "PUT", "/health", b"");
    assert_eq!(r.status, 405);
}
