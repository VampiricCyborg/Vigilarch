# web/ — the interactive demo page

The same ledger `vigil-sim` and `vigil-node` run natively, compiled to `wasm32` and driven
one action at a time from a browser. Append to either chain, exchange attestations, click an
entry to see its bracket, equivocate and watch a key get convicted while its withheld sibling
stays unsealed.

`index.html`, `style.css` and `app.js` are served exactly as written — no bundler, no npm, no
framework, no build step. `app.js` is a renderer only: every verdict on the page comes back
from `vigil-ledger` through `crates/vigil-wasm`, because a second implementation of chain,
attestation or bracketing logic in JavaScript is precisely the divergence invariant I2 exists
to prevent.

## Build and serve

Only the Rust needs compiling:

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.128 --locked   # match vigil-wasm's dependency

./web/build.sh
python -m http.server -d web 8080     # then open http://localhost:8080/
```

`build.sh` emits a bundler-free ES module into `web/pkg/` (`wasm-bindgen --target web`), which
`app.js` imports with a plain `import` statement. `pkg/` is generated and not tracked; rebuild
it from the workspace rather than committing it.

A plain HTTP server is required — `file://` cannot load an ES module or instantiate WASM, and
the server must send `.wasm` as `application/wasm`. Python's `http.server` already does.

## What to look for

The page is built around one distinction: a **bounded** window edge and an **open** one are
not the same claim, and must never look the same. A bounded edge is a solid cap naming the
attestation that closes it. An open edge is dashed, and the fill fades out towards it, because
nothing bounds the record on that side.

In this demo an append never carries `acks`, so no attestation ever precedes a record in its
own chain and the lower edge is always open to genesis. That is not a gap in the page — it is
the common field case, and `spec/02` §5.3 says why the v1 lower bound is weak.
