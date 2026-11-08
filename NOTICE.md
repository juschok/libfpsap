# NOTICE — provenance & licensing

`libfpsap` is licensed in its entirety under the **GNU Lesser General Public
License v3.0 or later (`LGPL-3.0-or-later`)**. The full terms are in
[`COPYING.LESSER`](COPYING.LESSER) (LGPLv3) and [`COPYING`](COPYING) (GPLv3,
which the LGPL incorporates by reference). Every source file carries an
`LGPL-3.0-or-later` SPDX header.

## Purpose: interoperability

This library performs the FairPlay "SAP" *mode-3* authentication handshake that
an AirPlay 2 **sender** must complete to be allowed to stream audio to AirPlay 2
receivers, so independent software can interoperate with those devices. It
authenticates a sender; it does **not** decrypt, play, or redistribute any
protected content.

No affiliation with, sponsorship by, or endorsement from Apple Inc. "AirPlay" is
a trademark of Apple Inc., used here only to describe interoperability.

## Attribution

The `fairplay_sapcore` component (`src/fairplay_sapcore.c/.h`) is **derived from**
prior reverse-engineering work and carries that lineage forward under the LGPL;
the rest of the library is original work of this project, released under the same
license. This project is indebted to, and credits, two upstream projects (both
`LGPL-3.0-or-later`):

- **omarroth/doubletake** — <https://github.com/omarroth/doubletake>
  — the FairPlay SAP core that `fairplay_sapcore` ultimately derives from, as of
  commit `8ccea5f`.
- **objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake** —
  <https://github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake>
  — the `fpsapcore` package this port was adapted from, which itself credits
  omarroth/doubletake.

If you redistribute `libfpsap`, keep this `NOTICE.md`, the LGPL SPDX headers, and
the `COPYING*` files with it, and make the corresponding source available as the
LGPL requires (dynamic linking via `dlopen` satisfies the LGPL's relink
condition).
