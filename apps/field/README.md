# Field PWA (M4-lite)

React + TypeScript + Vite over the `vigil-core` WASM build. A **plain PWA** — no
Capacitor, no native build, no MDM distribution. Ugly is fine; this app exists to prove
that the ledger works in a browser on a disconnected device, not to be pleasant.

Acceptance:

- Capture to persisted in under ten seconds, offline, from a cold start.
- A week of offline use followed by a reconnect loses nothing.

Both are demonstrated in `vigil-sim` and in the hosted demo rather than measured on real
hardware — there are no real devices in this project.

## What this app must not become

It runs `vigil-core` through `vigil-wasm` and holds no ledger logic of its own
(architectural invariant #2). If something here needs a chain walked, an attestation
checked or a merge resolved, that belongs in Rust and gets compiled to WASM. A
TypeScript reimplementation, even a temporary one, guarantees divergence bugs that
appear only under partition.

Build this early and badly, before the app is due. Feeling the capture-latency problem
in your hands will change the data model, and it is much cheaper to learn that before
the ledger's storage layer is settled.
