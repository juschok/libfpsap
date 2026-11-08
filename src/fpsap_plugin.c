/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * fpsap_plugin.c -- the libfpsap.so exported ABI, a thin wrapper over the
 * fp_crypto engine. See fpsap_plugin.h.
 */
#include "fpsap_plugin.h"
#include "fp_crypto.h"
#include "fairplay_sapcore.h"

uint32_t fpsap_abi_version(void)
{
    return FPSAP_ABI_VERSION;
}

void fpsap_build_m1(uint8_t capabilities, uint8_t m1[FPSAP_M1_LEN])
{
    fp_build_m1(capabilities, m1);
}

void fpsap_make_local_sap(const uint8_t entropy126[126], uint8_t sap[128])
{
    fp_make_local_sap(entropy126, sap);
}

int fpsap_m3_session(const uint8_t *m2, size_t m2_len,
                     const uint8_t sap[128], uint8_t m3[FPSAP_M3_LEN],
                     int *selected_mode)
{
    return fp_m3_session(m2, m2_len, sap, m3, selected_mode);
}

int fpsap_key_material(const uint8_t *m2, size_t m2_len,
                       const uint8_t sap[128],
                       uint8_t wrap_key[16], uint8_t mac_key[20],
                       int *selected_mode)
{
    return fp_key_material(m2, m2_len, sap, wrap_key, mac_key, selected_mode);
}

void fpsap_encrypt_body(const uint8_t plaintext[128], uint8_t out[128])
{
    fp_encrypt_body_mode3(plaintext, out);
}

void fpsap_decrypt_body(const uint8_t in[128], uint8_t out[128])
{
    fp_decrypt_body_mode3(in, out);
}

void fpsap_wrapping_key(const uint8_t sender_sap[128],
                        const uint8_t receiver_sap[128], uint8_t out_key[16])
{
    fp_wrapping_key(sender_sap, receiver_sap, out_key);
}

void fpsap_sap_descriptor(const uint8_t m3_sap[128],
                          const uint8_t m2_sap[128], uint8_t out[20])
{
    fp_sap_descriptor_for_sap(m3_sap, m2_sap, out);
}
