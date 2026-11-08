# libfpsap — FairPlay SAP crypto plugin

A small, standalone, `dlopen`-able plugin that performs the FairPlay **SAP
mode-3** authentication handshake an **AirPlay 2 sender** must complete to stream
audio to AirPlay 2 receivers. It exists for **interoperability** — it
authenticates a sender; it does **not** decrypt, play, or redistribute any
protected content.

It is meant to be **built and shipped separately** from any host application. A
host loads it at runtime across a tiny, stable C ABI; the Apple-derived white-box
AES tables and the LGPL-licensed engine live **here**, isolated behind that ABI,
so they stay out of the host binary. If the shared library is absent, the host
simply can't do the mode-3 handshake and falls back to whatever it does without
it.

## What it does

Turns an AirPlay 2 receiver's 142-byte `m2` challenge into the sender's 164-byte
`m3` response (`Phase 1` white-box AES → bridge → `Phase 2` analytical white-box
MD5), plus the `m1` framing and a per-session local SAP. Mode 3 only.

## Build

Freestanding C — only `<stdint.h>`/`<string.h>`, no external dependencies:

```sh
make           # -> lib/<os>/<arch>/libfpsap.<so|dylib>
```

Verify it offline against the bundled vectors (no device needed):

```sh
make check     # golden vectors: 142/142, message body: OK, session==frozen: OK
```

## Using it from a host

The host `dlopen`s `libfpsap.so` and calls the `fpsap_*` ABI below. Put the built
library somewhere the host can find it — on the loader path
(`LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`), next to the host, or via whatever path
the host accepts. `make install` copies it to `$(PREFIX)/lib`
(default `PREFIX=/usr/local`; override as needed):

```sh
make install PREFIX=/usr/local
```

## ABI (`src/fpsap_plugin.h`)

```c
uint32_t fpsap_abi_version(void);                         // == 1
void     fpsap_build_m1(uint8_t capabilities, uint8_t m1[16]);
void     fpsap_make_local_sap(const uint8_t entropy126[126], uint8_t sap[128]);
int      fpsap_m3_session(const uint8_t *m2, size_t len,
                          const uint8_t sap[128], uint8_t m3[164], int *mode);
```

Only the `fpsap_*` symbols are exported (`-fvisibility=hidden`); the engine stays
internal.

## Layout

| Path | What |
|---|---|
| `src/fp_crypto.c` | Phase 1 + Phase 2 + message-body cipher + framing |
| `src/fp_tables.c` | generated white-box tables |
| `src/fairplay_sapcore.c`, `src/fairplay_bridge.c` | the bridge stage |
| `src/fpsap_plugin.c` | the exported ABI wrapper |
| `src/fp_rtsp.c`, `src/fp_main.c` | standalone CLI/transport (not built by default) |
| `vectors/` | golden + conformance vectors for `make check` |

Provenance: reverse-engineered from Apple's FairPlay SAP for defensive
interoperability (an authentication handshake, not DRM / content keys). No
content is decrypted and no keys are extracted.

## License & attribution

Licensed in its entirety under **LGPL-3.0-or-later**
([`COPYING.LESSER`](COPYING.LESSER) + [`COPYING`](COPYING)); every source file
carries an `LGPL-3.0-or-later` SPDX header. See [`NOTICE.md`](NOTICE.md) for the
attribution and the source offer.

This work descends from and is indebted to two upstream projects (both
`LGPL-3.0-or-later`):

- **omarroth/doubletake** — <https://github.com/omarroth/doubletake>
- **objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake** —
  <https://github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake>

Not affiliated with or endorsed by Apple Inc.; "AirPlay" is a trademark of Apple
Inc., used only to describe interoperability.
