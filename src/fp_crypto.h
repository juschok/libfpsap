/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * fp_crypto.h -- the full FairPlay SAP mode-3 computation in C.
 *
 * This is the engine the handshake driver sits on top of. It turns a
 * receiver's m2 challenge into the sender's m3 response, with no Apple blob and
 * no network: Phase 1 (white-box AES) -> bridge -> Phase 2 (analytical white-box
 * MD5). The bridge is fairplay_sapcore.c / fairplay_bridge.c in this directory.
 *
 * Provenance: reverse-engineered from Apple's FairPlay SAP; defensive
 * interoperability research (an authentication handshake, not DRM / content
 * keys). Mode 3 only -- the white-box tables bake that mode's key schedule.
 */
#ifndef FP_CRYPTO_H
#define FP_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The only FairPlay message mode this code answers. */
#define FP_SUPPORTED_MODE 3

/* Record sizes on the wire. */
#define FP_M1_LEN 16
#define FP_M2_LEN 142
#define FP_M3_LEN 164

/* Parse-m2 result codes. */
enum {
    FP_OK = 0,
    FP_ERR_LEN = -1,     /* m2 is not 142 bytes                        */
    FP_ERR_FRAMING = -2, /* magic / version / length / marker is wrong */
    FP_ERR_MODE = -3     /* m2 selected a mode other than 3            */
};

/* ---- stage building blocks (exposed for the self-test) ---------------- */

/* Phase 1: 128-byte challenge payload -> 128-byte GP buffer. */
void fp_gp_buffer(const uint8_t payload[128], uint8_t gp[128]);

/* Phase 2: 64-byte x9 data (20-byte bridge head + 44-byte constant tail)
 * -> 20-byte response. */
void fp_phase2_from_x9(const uint8_t x9[64], uint8_t out[20]);

/* Full blobless response for the FROZEN session: payload -> 20-byte response.
 * This is the value the 142 golden vectors pin. */
void fp_exchange_blobless(const uint8_t payload[128], uint8_t out[20]);

/* m3 message-body cipher (mode-3 AES-CBC with Apple's baked round keys),
 * 128 bytes -> 128 bytes. */
void fp_encrypt_body_mode3(const uint8_t plaintext[128], uint8_t out[128]);

/* ---- framing ---------------------------------------------------------- */

/* Build the 16-byte m1 record. capabilities defaults to 3 (full). */
void fp_build_m1(uint8_t capabilities, uint8_t m1[FP_M1_LEN]);

/* Validate an m2 record and copy out its 128-byte challenge.
 * Returns FP_OK, or a negative FP_ERR_*; on FP_ERR_MODE *mode (if non-NULL)
 * is set to the mode the receiver selected. */
int fp_parse_m2(const uint8_t *m2, size_t len, uint8_t challenge[128], int *mode);

/* Frozen (replay) m3: splices the constant 144-byte prefix before the
 * computed 20-byte response. Works only against permissive mode-3 receivers.
 * Returns FP_OK or a negative FP_ERR_*. */
int fp_m3_frozen(const uint8_t *m2, size_t len, uint8_t m3[FP_M3_LEN], int *mode);

/* Session-aware m3: encrypts the caller's 128-byte local SAP into the body and
 * folds it into the response, so no two sessions emit the same frame -- what a
 * strict receiver (e.g. a HomePod) requires. Build local_sap with
 * fp_make_local_sap(). Returns FP_OK or a negative FP_ERR_*. */
int fp_m3_session(const uint8_t *m2, size_t len, const uint8_t local_sap[128],
                  uint8_t m3[FP_M3_LEN], int *mode);

/* Turn 126 bytes of entropy into a local SAP: [00 01] followed by the entropy,
 * matching what a native sender does (it overwrites the first two bytes 00 01). */
void fp_make_local_sap(const uint8_t entropy126[126], uint8_t local_sap[128]);

/* ---- audio-key wrapping (sender) -------------------------------------- */

/* CBC decrypt of a 128-byte mode-3 FairPlay message body (inverse of
 * fp_encrypt_body_mode3). Used to recover the receiver's SAP from m2. */
void fp_decrypt_body_mode3(const uint8_t in[128], uint8_t out[128]);

/* 16-byte AES wrapping key from the two session SAPs (the modified-MD5/SAP
 * KDF over prefix||sender_sap||receiver_sap||suffix). */
void fp_wrapping_key(const uint8_t sender_sap[128],
                     const uint8_t receiver_sap[128], uint8_t out_key[16]);

/* Parse m2 and emit the two FairPlay key-derivation halves the host needs to
 * wrap the audio key: wrap_key[16] and mac_key[20]. sender_sap == local_sap.
 * Returns FP_OK or a negative FP_ERR_*. */
int fp_key_material(const uint8_t *m2, size_t m2_len, const uint8_t local_sap[128],
                    uint8_t wrap_key[16], uint8_t mac_key[20], int *mode);

/* Constants exposed for the self-test. */
extern const uint8_t fp_frozen_local_sap[128];
extern const uint8_t fp_m3_prefix[144];

#ifdef __cplusplus
}
#endif

#endif
