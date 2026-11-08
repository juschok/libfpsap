/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * fpsap_plugin.h -- the stable C ABI exported by libfpsap.so.
 *
 * This is the only surface a host application (an AirPlay 2 sender) links against, via
 * dlopen/dlsym. Everything behind it -- the white-box AES tables, the bridge,
 * the analytical MD5 -- stays inside the shared object, which ships separately
 * from the host binary (the Apple-derived tables and the LGPL-licensed files
 * live here, not in the host). Keep this header dependency-free and additive:
 * never renumber or repurpose a symbol, bump FPSAP_ABI_VERSION for a break.
 */
#ifndef FPSAP_PLUGIN_H
#define FPSAP_PLUGIN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define FPSAP_API __declspec(dllexport)
#elif defined(__GNUC__)
#define FPSAP_API __attribute__((visibility("default")))
#else
#define FPSAP_API
#endif

#define FPSAP_ABI_VERSION 1u

/* Record sizes on the wire. */
#define FPSAP_M1_LEN 16
#define FPSAP_M2_LEN 142
#define FPSAP_M3_LEN 164

/* Result codes (match fp_crypto's FP_*). */
enum {
    FPSAP_OK = 0,
    FPSAP_ERR_LEN = -1,
    FPSAP_ERR_FRAMING = -2,
    FPSAP_ERR_MODE = -3
};

/* ABI version of this build; a host checks it == FPSAP_ABI_VERSION. */
FPSAP_API uint32_t fpsap_abi_version(void);

/* Build the 16-byte m1 record. Pass capabilities 0x03 (full) to steer a
 * receiver toward mode 3. */
FPSAP_API void fpsap_build_m1(uint8_t capabilities, uint8_t m1[FPSAP_M1_LEN]);

/* Turn 126 bytes of caller entropy into a 128-byte per-session local SAP. */
FPSAP_API void fpsap_make_local_sap(const uint8_t entropy126[126], uint8_t sap[128]);

/* Compute the session-aware m3 for a receiver's m2.
 * Returns FPSAP_OK, or a negative code; on FPSAP_ERR_MODE *selected_mode
 * (when non-NULL) is set to the mode the receiver chose. */
FPSAP_API int fpsap_m3_session(const uint8_t *m2, size_t m2_len,
                     const uint8_t sap[128], uint8_t m3[FPSAP_M3_LEN],
                     int *selected_mode);

/* Derive the two FairPlay key-wrapping halves for the audio stream key from
 * the receiver's m2 and the local SAP (the same SAP passed to
 * fpsap_m3_session): the 16-byte AES wrap key and the 20-byte HMAC-SHA1 MAC
 * key. The host generates a random 16-byte raw key + 16-byte mask and
 * assembles the 72-byte FPLY ekey:
 *   ekey[0:16]  = {'F','P','L','Y',1,2,1,0, 0,0,0,0x3c, 0,0,0,0}
 *   ekey[16:32] = mask
 *   ekey[32:36] = big-endian uint32(16)
 *   ekey[36:56] = HMAC-SHA1(mac_key, ekey[0:36] || raw_key)   (20 bytes)
 *   ekey[56:72] = AES-128-ECB(wrap_key, raw_key XOR mask)
 * and derives the stream audio key = SHA-512(raw_key || pairing_shared_secret)[:16].
 * Returns FPSAP_OK, or a negative code (on FPSAP_ERR_MODE *selected_mode is set). */
FPSAP_API int fpsap_key_material(const uint8_t *m2, size_t m2_len,
                       const uint8_t sap[128],
                       uint8_t wrap_key[16], uint8_t mac_key[20],
                       int *selected_mode);

/* ---- RECEIVER-side primitives (for a FairPlay SAP responder / MITM) ----
 * These expose the engine's building blocks so a host can act as the receiver:
 * generate an m2 from a known local SAP, recover the sender SAP from m3, derive
 * the wrapping + MAC keys, and unwrap the sender's ekey. All reuse the same
 * recovered white-box tables as the sender path. */

/* mode-3 FairPlay message body cipher (128B -> 128B) and its inverse. */
FPSAP_API void fpsap_encrypt_body(const uint8_t plaintext[128], uint8_t out[128]);
FPSAP_API void fpsap_decrypt_body(const uint8_t in[128], uint8_t out[128]);

/* 16-byte AES wrapping key from the two session SAPs. */
FPSAP_API void fpsap_wrapping_key(const uint8_t sender_sap[128],
                       const uint8_t receiver_sap[128], uint8_t out_key[16]);

/* 20-byte descriptor / HMAC key over (m3_sap, m2_sap). */
FPSAP_API void fpsap_sap_descriptor(const uint8_t m3_sap[128],
                       const uint8_t m2_sap[128], uint8_t out[20]);

#ifdef __cplusplus
}
#endif

#endif
