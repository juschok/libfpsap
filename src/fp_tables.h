/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Generated white-box tables for the FairPlay SAP handshake (see fp_tables.c).
 */
#ifndef FP_TABLES_H
#define FP_TABLES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Phase 1 white-box AES T-boxes (mode 3 key schedule baked in). */
extern const uint8_t  fp_wbaes_type_i[160][256];
extern const uint32_t fp_wbaes_type_ii[4][256];
extern const uint8_t  fp_wbaes_output_dec[16][256];

/* Phase 2 analytical white-box MD5 SPN tables. */
extern const uint8_t  fp_g_sbox[16][256];
extern const uint8_t  fp_spn1_core_tables[9][16][256];
extern const uint8_t  fp_spn1_trail_tables[16][256];
extern const uint8_t  fp_spn1_mixcol_rows[128][16];

#ifdef __cplusplus
}
#endif

#endif
