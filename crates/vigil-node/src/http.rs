//! The HTTP surface: a pure request router ([`dispatch`]) and the `tiny_http`
//! serve loop ([`serve`]) that feeds it.
//!
//! [`dispatch`] takes a method, a path, and a body and returns an
//! [`HttpResponse`] — no sockets, so it is exercised directly by the tests as
//! well as by the live server.

use std::sync::Arc;

use vigil_core::Hash;
use vigil_ledger::ExportError;

use crate::{CaptureError, Node, chain_json, window_edge_json};

/// A rendered response, independent of the HTTP transport.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, value: &serde_json::Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    fn error(status: u16, message: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": message }))
    }
}

/// Route one request. Pure: the only state it touches is `node`.
///
/// Endpoints:
///
/// - `GET  /health`                  — liveness, node key, chain length
/// - `POST /obs`                     — capture; body is the note text
/// - `GET  /obs/{id}/provenance`     — read-only bracket + chain verification
/// - `POST /export`                  — evidence pack for a JSON array of ids
#[must_use]
pub fn dispatch(node: &Node, method: &str, path: &str, body: &[u8]) -> HttpResponse {
    // Drop any query string; none of these endpoints take one.
    let path = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    match (method, segments.as_slice()) {
        ("GET", ["health"]) => health(node),
        ("POST", ["obs"]) => capture(node, body),
        ("GET", ["obs", id, "provenance"]) => provenance(node, id),
        ("POST", ["export"]) => export(node, body),

        // A path that exists under another method — report 405, not 404.
        (_, ["health"]) | (_, ["obs"]) | (_, ["export"]) | (_, ["obs", _, "provenance"]) => {
            HttpResponse::error(405, "method not allowed")
        }
        _ => HttpResponse::error(404, "no such endpoint"),
    }
}

fn health(node: &Node) -> HttpResponse {
    let h = node.health();
    HttpResponse::json(
        200,
        &serde_json::json!({
            "status": "ok",
            "node_pubkey": h.pubkey.to_string(),
            "chain_len": h.chain_len,
        }),
    )
}

fn capture(node: &Node, body: &[u8]) -> HttpResponse {
    let Ok(text) = std::str::from_utf8(body) else {
        return HttpResponse::error(400, "body is not valid UTF-8");
    };
    match node.capture(text) {
        Ok(c) => HttpResponse::json(
            201,
            &serde_json::json!({ "id": c.id.to_string(), "seq": c.seq }),
        ),
        Err(CaptureError::Empty) => HttpResponse::error(400, "capture body is empty"),
        Err(e @ CaptureError::Ledger(_)) => HttpResponse::error(500, &e.to_string()),
    }
}

fn provenance(node: &Node, id: &str) -> HttpResponse {
    let Some(id) = parse_hash(id) else {
        return HttpResponse::error(400, "observation id is not 64 hex characters");
    };
    match node.provenance(id) {
        Ok(Some(p)) => {
            let b = &p.bracket;
            HttpResponse::json(
                200,
                &serde_json::json!({
                    "observation": p.id.to_string(),
                    "author": p.author.to_string(),
                    "seq": p.seq,
                    "chain_verification": chain_json(&p.chain),
                    "sealed": b.sealed,
                    "upper_bound": b.upper_bound.map(|h| h.to_string()),
                    "lower_bound": b.lower_bound.map(|h| h.to_string()),
                    "witness_depth": b.witness_depth,
                    "unwitnessed_window": {
                        "lower": window_edge_json(&b.unwitnessed_window.lower),
                        "upper": window_edge_json(&b.unwitnessed_window.upper),
                    },
                    "disputed": b.disputed,
                }),
            )
        }
        Ok(None) => HttpResponse::error(404, "no record with that id"),
        Err(e) => HttpResponse::error(500, &format!("{e:#}")),
    }
}

fn export(node: &Node, body: &[u8]) -> HttpResponse {
    let ids: Vec<String> = match serde_json::from_slice(body) {
        Ok(ids) => ids,
        Err(_) => {
            return HttpResponse::error(
                400,
                "body must be a JSON array of observation ids, e.g. [\"<64 hex>\", ...]",
            );
        }
    };
    let mut claims = Vec::with_capacity(ids.len());
    for s in &ids {
        let Some(h) = parse_hash(s) else {
            return HttpResponse::error(400, &format!("not a 64-hex observation id: {s}"));
        };
        claims.push(h);
    }

    match node.export(&claims) {
        Ok(bytes) => HttpResponse {
            status: 200,
            content_type: "application/octet-stream",
            body: bytes,
        },
        Err(ExportError::ClaimNotHeld(h)) => HttpResponse::error(
            400,
            &format!("claim names a record this node does not hold: {h}"),
        ),
        Err(ExportError::Store(e)) => HttpResponse::error(500, &e.to_string()),
    }
}

fn parse_hash(s: &str) -> Option<Hash> {
    let bytes = hex::decode(s.trim()).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(Hash(arr))
}

// -- the live server --------------------------------------------------------

/// Run the blocking `tiny_http` serve loop over `server`, dispatching every
/// request to `node`. Returns only if the server socket closes.
///
/// A small fixed pool of worker threads pulls from the shared server so one
/// in-flight request never delays the next — though at this scale every handler
/// is an in-memory operation that returns in microseconds.
pub fn serve(node: Arc<Node>, server: tiny_http::Server) {
    let server = Arc::new(server);
    let workers = 4;
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let server = Arc::clone(&server);
        let node = Arc::clone(&node);
        handles.push(std::thread::spawn(move || {
            while let Ok(request) = server.recv() {
                serve_one(&node, request);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn serve_one(node: &Node, mut request: tiny_http::Request) {
    let method = request.method().as_str().to_owned();
    let url = request.url().to_owned();

    let mut body = Vec::new();
    if std::io::Read::read_to_end(request.as_reader(), &mut body).is_err() {
        let _ = request.respond(
            tiny_http::Response::from_string("could not read request body").with_status_code(400),
        );
        return;
    }

    let response = dispatch(node, &method, &url, &body);
    let header =
        tiny_http::Header::from_bytes(&b"Content-Type"[..], response.content_type.as_bytes())
            .expect("static header is well-formed");

    let _ = request.respond(
        tiny_http::Response::from_data(response.body)
            .with_status_code(response.status)
            .with_header(header),
    );
}
