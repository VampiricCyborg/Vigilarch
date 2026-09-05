# Field PWA (M4)

React + TypeScript + Vite over the `vigil-core` WASM build, wrapped in Capacitor for
camera, BLE, background sync and the hardware keystore. Android-first — that is what
field crews carry.

Acceptance (§14 M4): capture-to-persisted under 10 s in airplane mode on a low-end
Android with the app cold-started; a week of offline use followed by reconnect loses
nothing; background sync costs under 3%/day of battery.

Build a deliberately ugly version of this early — before M4 proper — because feeling the
capture-latency problem in your hands will change the data model (§14, sequencing).
