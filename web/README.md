# web/ — the demo site

Two pages over one WebAssembly module.

| File | What it is |
|---|---|
| `index.html` + `landing.css` + `landing.js` | The landing page: what the project claims, what it refuses to claim, and a hero card that runs a five-call scenario through the real ledger on load |
| `demo.html` + `style.css` + `app.js` | The interactive dashboard: drive the ledger one action at a time |
| `base.css` | Tokens and the header bar both pages share, so the two cannot drift apart |
| `pkg/` | `wasm-bindgen --target web` output. Generated, not tracked |

The dashboard is the same ledger `vigil-sim` and `vigil-node` run natively, compiled to
`wasm32` and driven one action at a time from a browser. Append to either chain, exchange
attestations, click an entry to see its bracket, equivocate and watch a key get convicted
while its withheld sibling stays unsealed.

Everything is served exactly as written — no bundler, no npm, no framework, no build step for
the pages themselves. `app.js` and `landing.js` are renderers only: every verdict on either
page comes back from `vigil-ledger` through `crates/vigil-wasm`, because a second
implementation of chain, attestation or bracketing logic in JavaScript is precisely the
divergence invariant I2 exists to prevent.

## Every claim on the landing page is sourced

The landing page carries numbers — seed counts, pass rates, test counts, pack sizes — and
each one is quoted from a file in this repository, with the source named in an HTML comment
above the block that uses it. Nothing on it is estimated or rounded, and where the repository
records that something is *not* done (the licence, the mule-relay gap, the absence of a
coverage-guided fuzzer) the page says so at the same volume as the things that are.

The hero card is the load-bearing case: it holds no literal at all. It calls `append`,
`exchangeAttestation`, `equivocate` and `bracket` on load and prints what comes back. Change
a string in `SCENARIO` at the top of `landing.js` and every content address on the card
changes with it, because they are BLAKE3 addresses of the objects the ledger actually built.

## Build and serve

Only the Rust needs compiling:

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.128 --locked   # match vigil-wasm's dependency

./web/build.sh
python -m http.server -d web 8080     # landing at /, dashboard at /demo.html
```

`build.sh` emits a bundler-free ES module into `web/pkg/` (`wasm-bindgen --target web`), which
`app.js` imports with a plain `import` statement and `landing.js` imports dynamically — the
landing page degrades to an honest "module not built" card rather than a blank page when
`pkg/` is absent, which is the state a fresh clone is in. `pkg/` is generated and not tracked; rebuild
it from the workspace rather than committing it.

A plain HTTP server is required — `file://` cannot load an ES module or instantiate WASM, and
the server must send `.wasm` as `application/wasm`. Python's `http.server` already does.

## What to look for

Both pages are built around one distinction: a **bounded** window edge and an **open** one are
not the same claim, and must never look the same. A bounded edge is a solid cap naming the
attestation that closes it. An open edge is dashed, and the fill fades out towards it, because
nothing bounds the record on that side.

In this demo an append never carries `acks`, so no attestation ever precedes a record in its
own chain and the lower edge is always open to genesis. That is not a gap in the page — it is
the common field case, and `spec/02` §5.3 says why the v1 lower bound is weak.
