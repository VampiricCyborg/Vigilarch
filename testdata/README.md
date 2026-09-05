# testdata/

Golden wire vectors and recorded partition scenarios. Both are checked in from commit
one (§16.2).

- **Golden vectors** pin the canonical encoding. They are cross-verified byte-for-byte
  between native and WASM builds; a divergence means content addresses differ across
  platforms, which means the ledger silently forks.
- **Scenarios** are seeded `vigil-sim` scripts: partition topologies, clock rollback,
  equivocation, withholding, mule routes. Each is reproducible from its seed, so a
  failure found in CI can be replayed exactly on a laptop.
