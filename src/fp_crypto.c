/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * fp_crypto.c -- Phase 1 (white-box AES), Phase 2 (analytical white-box MD5),
 * the m3 message-body cipher, and the m1/m2/m3 framing, ported from the Go
 * reference (fpbridge / fpsapcore / fairplayhash). The bridge stage between the
 * two phases is fairplay_sapcore.c + fairplay_bridge.c in this directory.
 */
#include "fp_crypto.h"
#include "fp_tables.h"
#include "fairplay_sapcore.h"
#include "fairplay_bridge.h"

#include <string.h>

/* ===================================================================== */
/* helpers                                                               */
/* ===================================================================== */

static uint32_t rotr32(uint32_t v, unsigned r)
{
    r &= 31u;
    return (v >> r) | (v << ((32u - r) & 31u));
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ===================================================================== */
/* Phase 1 -- white-box AES (fpbridge/wbaes_*.go)                        */
/* ===================================================================== */

/* wbaesTypeIOrder[round][pos] */
static const int wbaes_type_i_order[10][16] = {
    {32, 132, 88, 44, 141, 41, 85, 129, 82, 138, 38, 94, 35, 135, 91, 47},
    {64, 20, 120, 76, 29, 73, 117, 17, 114, 26, 70, 126, 67, 23, 123, 79},
    {96, 52, 8, 108, 61, 105, 5, 49, 2, 58, 102, 14, 99, 55, 11, 111},
    {128, 84, 40, 140, 93, 137, 37, 81, 34, 90, 134, 46, 131, 87, 43, 143},
    {16, 116, 72, 28, 125, 25, 69, 113, 66, 122, 22, 78, 19, 119, 75, 31},
    {48, 4, 104, 60, 13, 57, 101, 1, 98, 10, 54, 110, 51, 7, 107, 63},
    {80, 36, 136, 92, 45, 89, 133, 33, 130, 42, 86, 142, 83, 39, 139, 95},
    {112, 68, 24, 124, 77, 121, 21, 65, 18, 74, 118, 30, 115, 71, 27, 127},
    {0, 100, 56, 12, 109, 9, 53, 97, 50, 106, 6, 62, 3, 103, 59, 15},
    {144, 148, 152, 156, 157, 153, 149, 145, 146, 154, 150, 158, 147, 151, 155, 159},
};

static const int wbaes_mixing_sigma[16] =
    {0, 6, 9, 15, 1, 5, 11, 12, 2, 4, 8, 13, 3, 7, 10, 14};
static const int wbaes_mixing_sigma_inv[16] =
    {0, 4, 8, 12, 9, 5, 1, 13, 10, 2, 14, 6, 7, 11, 15, 3};
static const int wbaes_shift_rows_cols[4][4] = {
    {0, 13, 10, 7}, {4, 1, 14, 11}, {8, 5, 2, 15}, {12, 9, 6, 3},
};
static const int gp_buffer_perm[16] =
    {0, 4, 8, 12, 13, 9, 5, 1, 2, 10, 6, 14, 3, 7, 11, 15};

static const uint8_t wbaes_xor_consts[10][16] = {
    {0x3a, 0x91, 0xb9, 0x37, 0xdc, 0xad, 0x0a, 0x95, 0x81, 0x1b, 0x1c, 0x4d, 0xdc, 0xa0, 0xdf, 0x74},
    {0x02, 0xcd, 0x4c, 0x80, 0xd1, 0x6a, 0x7d, 0x9b, 0x6a, 0x31, 0xe5, 0x1a, 0xe4, 0x81, 0xec, 0x1a},
    {0xd4, 0xbf, 0xa9, 0x22, 0x89, 0x92, 0x96, 0x0b, 0x17, 0x4e, 0x60, 0x10, 0xf2, 0xa8, 0x6d, 0x83},
    {0x2a, 0x29, 0x5a, 0x5e, 0xb0, 0x4c, 0xd6, 0x25, 0xd7, 0x73, 0x3f, 0xc9, 0x8b, 0xd4, 0xef, 0x7f},
    {0xfd, 0xdb, 0x1f, 0x37, 0x5f, 0x76, 0xda, 0x3c, 0xcf, 0x58, 0x1c, 0x83, 0xb3, 0xdc, 0x0b, 0x60},
    {0x08, 0x24, 0xe3, 0x6d, 0x8a, 0xe9, 0x95, 0x95, 0x9f, 0xf8, 0x7d, 0x2b, 0x61, 0x98, 0xcd, 0xe9},
    {0xee, 0x51, 0xdd, 0x88, 0xc4, 0xc4, 0x91, 0x70, 0x39, 0x21, 0x4a, 0x8f, 0x2d, 0xa8, 0x99, 0x7d},
    {0xa1, 0x0e, 0xee, 0x6d, 0x22, 0xbc, 0x10, 0xcc, 0xd3, 0x4e, 0x6f, 0x28, 0xc8, 0xbf, 0xcd, 0xb8},
    {0x47, 0xa7, 0xae, 0x22, 0xfc, 0xe5, 0x62, 0xdf, 0xb3, 0x93, 0x38, 0x56, 0xda, 0x34, 0x9c, 0xae},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

static uint8_t wbaes_mixing_consts[9][16];
static int wbaes_mixing_ready = 0;

/* One round's MixColumns via the four Type-II words, matching the Go byte
 * scatter exactly (the scatter is NOT the plain column order). */
static void wbaes_mixcols(const uint8_t sub[16], uint8_t state[16])
{
    uint32_t cols[4];
    int col;
    for (col = 0; col < 4; col++) {
        const int *p = wbaes_shift_rows_cols[col];
        cols[col] = fp_wbaes_type_ii[0][sub[p[0]]] ^
                    fp_wbaes_type_ii[1][sub[p[1]]] ^
                    fp_wbaes_type_ii[2][sub[p[2]]] ^
                    fp_wbaes_type_ii[3][sub[p[3]]];
    }
    state[0] = (uint8_t)cols[0];
    state[1] = (uint8_t)cols[1];
    state[2] = (uint8_t)cols[2];
    state[3] = (uint8_t)cols[3];
    state[4] = (uint8_t)(cols[2] >> 8);
    state[5] = (uint8_t)(cols[1] >> 8);
    state[6] = (uint8_t)(cols[0] >> 8);
    state[7] = (uint8_t)(cols[3] >> 8);
    state[8] = (uint8_t)(cols[2] >> 16);
    state[9] = (uint8_t)(cols[0] >> 16);
    state[10] = (uint8_t)(cols[3] >> 16);
    state[11] = (uint8_t)(cols[1] >> 16);
    state[12] = (uint8_t)(cols[1] >> 24);
    state[13] = (uint8_t)(cols[2] >> 24);
    state[14] = (uint8_t)(cols[3] >> 24);
    state[15] = (uint8_t)(cols[0] >> 24);
}

static void wbaes_build_mixing_consts(void)
{
    uint8_t zero_state[16];
    int rnd, i;
    if (wbaes_mixing_ready) {
        return;
    }
    memset(zero_state, 0, sizeof zero_state);
    for (rnd = 0; rnd < 9; rnd++) {
        const int *order = wbaes_type_i_order[rnd];
        const uint8_t *xorc = wbaes_xor_consts[rnd];
        uint8_t t0[16], sub_zero[16];
        for (i = 0; i < 16; i++) {
            t0[i] = fp_wbaes_type_i[order[i]][zero_state[i]];
        }
        for (i = 0; i < 16; i++) {
            sub_zero[i] = (uint8_t)(t0[i] ^ xorc[i]);
        }
        for (i = 0; i < 16; i++) {
            wbaes_mixing_consts[rnd][i] =
                (uint8_t)(t0[wbaes_mixing_sigma[i]] ^ sub_zero[i]);
        }
        wbaes_mixcols(sub_zero, zero_state);
    }
    wbaes_mixing_ready = 1;
}

/* WB-AES core (rounds 1-9 + round-10 Type-I), returns raw round-10 output. */
static void wbaes_block_core(const uint8_t input[16], uint8_t raw[16])
{
    uint8_t state[16];
    int rnd, i;
    wbaes_build_mixing_consts();
    for (i = 0; i < 16; i++) {
        state[i] = input[wbaes_mixing_sigma_inv[i]];
    }
    for (rnd = 0; rnd < 9; rnd++) {
        const int *order = wbaes_type_i_order[rnd];
        const uint8_t *mixc = wbaes_mixing_consts[rnd];
        uint8_t type_i_out[16], sub[16];
        for (i = 0; i < 16; i++) {
            type_i_out[i] = fp_wbaes_type_i[order[i]][state[i]];
        }
        for (i = 0; i < 16; i++) {
            sub[i] = (uint8_t)(type_i_out[wbaes_mixing_sigma[i]] ^ mixc[i]);
        }
        wbaes_mixcols(sub, state);
    }
    {
        const int *order9 = wbaes_type_i_order[9];
        for (i = 0; i < 16; i++) {
            raw[i] = fp_wbaes_type_i[order9[i]][state[i]];
        }
    }
}

void fp_gp_buffer(const uint8_t payload[128], uint8_t gp[128])
{
    int block, i;
    for (block = 0; block < 8; block++) {
        uint8_t raw[16], block_out[16];
        wbaes_block_core(&payload[block * 16], raw);
        if (block == 0) {
            for (i = 0; i < 16; i++) {
                block_out[gp_buffer_perm[i]] = fp_wbaes_output_dec[i][raw[i]];
            }
            memcpy(&gp[0], block_out, 16);
        } else {
            for (i = 0; i < 16; i++) {
                block_out[gp_buffer_perm[i]] = (uint8_t)(raw[i] ^ 0x0F);
            }
            for (i = 0; i < 16; i++) {
                gp[block * 16 + i] =
                    (uint8_t)(block_out[i] ^ payload[(block - 1) * 16 + i]);
            }
        }
    }
}

/* ===================================================================== */
/* Phase 2 -- analytical white-box MD5 (fairplayhash)                    */
/* ===================================================================== */

static const uint32_t ADD_CONSTS[64] = {
    0x9695377e, 0xa7f24a5c, 0xe34b03e1, 0x80e861f4,
    0xb4a6a2b5, 0x06b25930, 0x675ad919, 0xbc712807,
    0x28ab2bde, 0x4a6f8ab5, 0xbf29eeb7, 0x48876ac4,
    0x2abaa428, 0xbcc30499, 0x65a3d694, 0x08de9b27,
    0xb548b868, 0x86940647, 0xe588ed57, 0xa8e15ab0,
    0x9559a363, 0xc16ea759, 0x97cc7987, 0xa6fe8ece,
    0xe10c60ec, 0x82619adc, 0xb3ffa08d, 0x0484a7f3,
    0x690e7c0b, 0xbc1a36fe, 0x269995df, 0x4c54df90,
    0xbf24cc48, 0x469c8987, 0x2cc7f428, 0xbd0fcb12,
    0x63e97d4a, 0x0b0962af, 0xb5e5de66, 0x7dea4f76,
    0xe7c611cc, 0xa9cbbb00, 0x9419c38b, 0xc3b2b00b,
    0x98ff633f, 0xa6062ceb, 0xdecd0ffe, 0x83d6e96b,
    0xb353b54a, 0x0255929d, 0x6abeb6ad, 0xbbbe333f,
    0x2485ecc9, 0x4e375f98, 0xbf1a8783, 0x44aef0d7,
    0x2ed31155, 0xbd5779e6, 0x622bd61a, 0x0d32a4a7,
    0xb67e1188, 0x7c65853b, 0xea0265c1, 0xaab16697,
};

static const uint32_t OUT_BIASES[64] = {
    0x1597aaf6, 0x4afee74e, 0x00a29db4, 0x28f24e7a,
    0x6823fe3e, 0x1e57a66c, 0x5f620c23, 0x7799deed,
    0x53b05079, 0x18ce4458, 0x71f50e9a, 0x1e97e2bd,
    0x4cb53c72, 0xf8d73fff, 0x40d9b2a2, 0x79fa6a78,
    0x3a2bf366, 0x483b376d, 0x6a883a49, 0x0a9e770c,
    0x7429c0e8, 0x0d0e4be5, 0x54df4cee, 0x26d52560,
    0x158c11bb, 0x0507ad81, 0x2a6f27d6, 0x67a96b8d,
    0x60707d13, 0x5a6e8346, 0x2cdf0deb, 0x6042060d,
    0x7b1c618c, 0x303b17fa, 0x2d9a7b6a, 0x664b944a,
    0x0bdccf3e, 0x10086643, 0x19aef3f8, 0x2efba790,
    0x06471876, 0x55064565, 0x6e3dd970, 0x2344baed,
    0x16c8e4af, 0x0cdb4428, 0x1fdada1f, 0x0e0a772d,
    0x0340f8af, 0x04ef307d, 0x7345d54b, 0x568a3ca9,
    0x6407b56c, 0x5ba36840, 0x77df87c0, 0x3fb93ddc,
    0x11686a25, 0x36ac9c46, 0x2203aab4, 0x1df07d7b,
    0x72624929, 0x7fb4b8eb, 0x46cedb6b, 0x00000000,
};

static const unsigned ROR_AMOUNTS[64] = {
    25, 20, 15, 10, 25, 20, 15, 10, 25, 20, 15, 10, 25, 20, 15, 10,
    27, 23, 18, 12, 27, 23, 18, 12, 27, 23, 18, 12, 27, 23, 18, 12,
    28, 21, 16, 9, 28, 21, 16, 9, 28, 21, 16, 9, 28, 21, 16, 9,
    26, 22, 17, 11, 26, 22, 17, 11, 26, 22, 17, 11, 26, 22, 17, 11,
};

static const int MSG_SCHEDULE[64] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
};

static const uint32_t ROUND8_INITIAL_STATE[4] =
    {0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216};
static const uint32_t NORMAL_ROUND_IV[4] =
    {0x1d4a4587, 0x92f39fcc, 0x1d87d836, 0xcdc86697};

#define NEON_XOR_CONST 0x7efd6cfau
#define NEON_AND_CONST 0xfdfad9f4u
#define NEON_ADD_CONST 0xc1d80000u

/* bridgeVreg1/2/3 (each lane equals these 32-bit values). */
#define BRIDGE_VREG1 0x7efd6cfau
#define BRIDGE_VREG2 0xc1d80000u
#define BRIDGE_VREG3 0xfdfad9f4u

/* The NEON prologue block transform: one 128-bit (4x32) lane group. */
static void neon_block(uint64_t v0lo, uint64_t v0hi,
                       uint32_t xor_mask, uint32_t and_mask, uint32_t add_bias,
                       uint32_t out[4])
{
    uint32_t lanes_lo[2], lanes_hi[2];
    int k;
    lanes_lo[0] = (uint32_t)v0lo;
    lanes_lo[1] = (uint32_t)(v0lo >> 32);
    lanes_hi[0] = (uint32_t)v0hi;
    lanes_hi[1] = (uint32_t)(v0hi >> 32);
    for (k = 0; k < 2; k++) {
        uint32_t d = lanes_lo[k];
        uint32_t t = d ^ xor_mask;
        uint32_t s = (d << 1) & and_mask;
        out[k] = t + s + add_bias;
    }
    for (k = 0; k < 2; k++) {
        uint32_t d = lanes_hi[k];
        uint32_t t = d ^ xor_mask;
        uint32_t s = (d << 1) & and_mask;
        out[2 + k] = t + s + add_bias;
    }
}

/* hiddenFromStaging: 4x neonBlock over a 64-byte message, constant masks. */
static void hidden_from_staging(const uint8_t src[64], uint32_t h[16])
{
    int b;
    for (b = 0; b < 4; b++) {
        uint64_t lo = load_le64(&src[b * 16]);
        uint64_t hi = load_le64(&src[b * 16 + 8]);
        neon_block(lo, hi, NEON_XOR_CONST, NEON_AND_CONST, NEON_ADD_CONST,
                   &h[b * 4]);
    }
}

/* The state-dependent Group 1->2 shuffle (prologue.go shuffleHiddenG2Into). */
static void shuffle_hidden_g2(const uint32_t g0[16], uint32_t aEnc, uint32_t bEnc,
                              uint32_t cEnc, uint32_t dEnc, uint32_t out[16])
{
    uint32_t h[16];
    uint32_t j, tmp;
    memcpy(h, g0, sizeof h);
#define SWAP(ix, jj)         \
    do {                     \
        j = (jj) & 15u;      \
        tmp = h[ix];         \
        h[ix] = h[j];        \
        h[j] = tmp;          \
    } while (0)
    SWAP(0, aEnc ^ 3u);
    SWAP(1, bEnc ^ 0xdu);
    SWAP(2, cEnc ^ 0xbu);
    SWAP(3, dEnc ^ 6u);
    SWAP(4, (aEnc >> 4) ^ 1u);
    SWAP(5, (bEnc >> 4));
    SWAP(6, (cEnc >> 4) ^ 0xeu);
    SWAP(7, (dEnc >> 4) ^ 4u);
#undef SWAP
    memcpy(out, h, sizeof h);
}

/* RoundC_MD5Plain: plain-MD5 equivalent of the white-box round, with the
 * sub-round-17 anomaly folded in and the state-dependent shuffle at i==32. */
static void roundc_md5_plain(uint32_t state[4], const uint32_t g0[16])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t g2[16] = {0};
    int have_g2 = 0;
    int i;
    for (i = 0; i < 64; i++) {
        uint32_t f, msg, tmp, addc;
        if (i == 32 && !have_g2) {
            shuffle_hidden_g2(g0,
                              a ^ OUT_BIASES[28],
                              b ^ OUT_BIASES[31],
                              c ^ OUT_BIASES[30],
                              d ^ OUT_BIASES[29],
                              g2);
            have_g2 = 1;
        }
        switch (i >> 4) {
        case 0: f = d ^ (b & (c ^ d)); break;
        case 1: f = c ^ (d & (b ^ c)); break;
        case 2: f = b ^ c ^ d; break;
        default: f = c ^ (b | ~d); break;
        }
        msg = (i < 32) ? g0[MSG_SCHEDULE[i]] : g2[MSG_SCHEDULE[i]];
        addc = ADD_CONSTS[i];
        if (i == 17) {
            addc += OUT_BIASES[13]; /* anomalyEncRound = 17 - 4 */
        }
        tmp = a + msg + f + addc;
        tmp = rotr32(tmp, ROR_AMOUNTS[i]);
        a = d;
        d = c;
        c = b;
        b = tmp + b;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void be_round_output(const uint32_t s[4], uint8_t o[16])
{
    int w;
    for (w = 0; w < 4; w++) {
        store_be32(&o[w * 4], s[w]);
    }
}

static void bswap_words16(const uint8_t in[16], uint8_t o[16])
{
    int w;
    for (w = 0; w < 4; w++) {
        o[w * 4 + 0] = in[w * 4 + 3];
        o[w * 4 + 1] = in[w * 4 + 2];
        o[w * 4 + 2] = in[w * 4 + 1];
        o[w * 4 + 3] = in[w * 4 + 0];
    }
}

/* ---- SPN#1 ------------------------------------------------------------ */

static const int SPN1_SHIFT_ROWS[16] =
    {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
static const uint8_t SPN1_CORE_INPUT[16] = {
    0x0f, 0x54, 0x5e, 0x5a, 0xb7, 0x7e, 0x16, 0x80,
    0x1a, 0xed, 0xd5, 0x81, 0xd0, 0x87, 0x26, 0xdc};
static const uint8_t SPN1_MIXCOL_CONST[16] = {
    0x0c, 0x48, 0x79, 0x5f, 0x0c, 0x48, 0x79, 0x5f,
    0x0c, 0x48, 0x79, 0x5f, 0x0c, 0x48, 0x79, 0x5f};

/* Reference bit-by-bit GF(2)-affine MixColumns (runs only 9x per hash). */
static void spn1_mixcolumns(const uint8_t in[16], uint8_t out[16])
{
    int ob, ib;
    memset(out, 0, 16);
    for (ob = 0; ob < 128; ob++) {
        uint8_t acc = 0;
        const uint8_t *row = fp_spn1_mixcol_rows[ob];
        for (ib = 0; ib < 128; ib++) {
            if ((row[ib >> 3] >> (ib & 7)) & 1) {
                acc ^= (uint8_t)((in[ib >> 3] >> (ib & 7)) & 1);
            }
        }
        acc ^= (uint8_t)((SPN1_MIXCOL_CONST[ob >> 3] >> (ob & 7)) & 1);
        if (acc) {
            out[ob >> 3] |= (uint8_t)(1u << (ob & 7));
        }
    }
}

static void spn1_apply_trailing(const uint8_t in[16], uint8_t out[16])
{
    int p;
    for (p = 0; p < 16; p++) {
        out[p] = fp_spn1_trail_tables[p][in[SPN1_SHIFT_ROWS[p]]];
    }
}

static void spn1(uint32_t ro[20][4], uint8_t out[16])
{
    uint8_t state[16];
    int r, pos, w;
    memcpy(state, SPN1_CORE_INPUT, 16);
    for (r = 0; r < 9; r++) {
        uint8_t stage1[16], mixed[16];
        for (pos = 0; pos < 16; pos++) {
            stage1[pos] = fp_spn1_core_tables[r][pos][state[SPN1_SHIFT_ROWS[pos]]];
        }
        spn1_mixcolumns(stage1, mixed);
        for (w = 0; w < 4; w++) {
            store_be32(&state[w * 4], load_be32(&mixed[w * 4]) ^ ro[10 + r][w]);
        }
    }
    spn1_apply_trailing(state, out);
}

/* ---- tail SPN --------------------------------------------------------- */

static const int TAIL_SPN_TYPE_I[9][16] = {
    {47, 94, 141, 44, 91, 138, 41, 88, 135, 38, 85, 132, 35, 82, 129, 32},
    {79, 126, 29, 76, 123, 26, 73, 120, 23, 70, 117, 20, 67, 114, 17, 64},
    {111, 14, 61, 108, 11, 58, 105, 8, 55, 102, 5, 52, 99, 2, 49, 96},
    {143, 46, 93, 140, 43, 90, 137, 40, 87, 134, 37, 84, 131, 34, 81, 128},
    {31, 78, 125, 28, 75, 122, 25, 72, 119, 22, 69, 116, 19, 66, 113, 16},
    {63, 110, 13, 60, 107, 10, 57, 104, 7, 54, 101, 4, 51, 98, 1, 48},
    {95, 142, 45, 92, 139, 42, 89, 136, 39, 86, 133, 36, 83, 130, 33, 80},
    {127, 30, 77, 124, 27, 74, 121, 24, 71, 118, 21, 68, 115, 18, 65, 112},
    {15, 62, 109, 12, 59, 106, 9, 56, 103, 6, 53, 100, 3, 50, 97, 0},
};
static const int TAIL_SPN_INV_SHIFT_ROWS[16] =
    {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
static const uint8_t TAIL_SPN_XOR_MASK[16] = {
    0x67, 0xbc, 0x54, 0xc0, 0x8e, 0x32, 0x85, 0x1b,
    0x50, 0xd2, 0x12, 0x5f, 0x68, 0xb7, 0x40, 0xa5};

static void tail_spn(const uint8_t input[16], const uint8_t mix_table[144],
                     uint8_t out[16])
{
    uint8_t state[16];
    int round, pos, col;
    memcpy(state, input, 16);
    for (round = 0; round < 9; round++) {
        uint32_t cols[4];
        if (round > 0) {
            uint8_t ns[16];
            for (pos = 0; pos < 16; pos++) {
                int src = TAIL_SPN_INV_SHIFT_ROWS[pos];
                int idx = TAIL_SPN_TYPE_I[round][15 - pos];
                ns[pos] = (uint8_t)(fp_wbaes_type_i[idx][state[src]] ^
                                    mix_table[(8 - round) * 16 + pos]);
            }
            memcpy(state, ns, 16);
        }
        for (col = 0; col < 4; col++) {
            cols[col] = fp_wbaes_type_ii[0][state[col * 4 + 0]] ^
                        fp_wbaes_type_ii[1][state[col * 4 + 1]] ^
                        fp_wbaes_type_ii[2][state[col * 4 + 2]] ^
                        fp_wbaes_type_ii[3][state[col * 4 + 3]];
        }
        for (col = 0; col < 4; col++) {
            state[col * 4 + 0] = (uint8_t)cols[col];
            state[col * 4 + 1] = (uint8_t)(cols[col] >> 8);
            state[col * 4 + 2] = (uint8_t)(cols[col] >> 16);
            state[col * 4 + 3] = (uint8_t)(cols[col] >> 24);
        }
    }
    for (pos = 0; pos < 16; pos++) {
        out[pos] = (uint8_t)(fp_wbaes_type_i[144 + pos][state[TAIL_SPN_INV_SHIFT_ROWS[pos]]] ^
                             TAIL_SPN_XOR_MASK[pos]);
    }
}

/* ---- the g-box tail round (TailInput) --------------------------------- */

static const int G_PERM[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};

static void tail_input(uint32_t ro[20][4], uint8_t out[16])
{
    uint8_t be8[16], be18[16];
    int p;
    be_round_output(ro[8], be8);
    be_round_output(ro[18], be18);
    for (p = 0; p < 16; p++) {
        out[p] = (uint8_t)(fp_g_sbox[p][be8[G_PERM[p]]] ^ be18[p]);
    }
}

/* R8/R19 staging message suffixes (spn1_r8r19.go). */
static const uint8_t R8_SUFFIX[48] = {
    0xa0, 0x2b, 0xc2, 0xaf, 0xfb, 0xfc, 0xef, 0x49, 0x5e, 0xac, 0x67, 0xfe, 0xcb, 0xfb, 0xf6, 0xbe,
    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t MD_PAD_LEN[32] = {
    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* ===================================================================== */
/* Phase 2 top level                                                     */
/* ===================================================================== */

void fp_phase2_from_x9(const uint8_t x9[64], uint8_t out[20])
{
    uint32_t base[16], ns_vreg0[4];
    uint32_t ro[20][4];
    uint8_t mix_table[144];
    uint8_t spn1_out[16], tail_in[16], tail_out[16];
    int k, b, w;

    /* bridgeNeonState: Vreg0 = neonBlock(x9[0:16], Vreg1, Vreg3, Vreg2). */
    neon_block(load_le64(&x9[0]), load_le64(&x9[8]),
               BRIDGE_VREG1, BRIDGE_VREG3, BRIDGE_VREG2, ns_vreg0);

    /* ComputeHiddenWords(ns, x9, round 0): hidden[0..3] = Vreg0 directly,
     * blocks 1..3 from x9[0x10..0x3F] through the round-0 masks (== bridge
     * Vregs, which equal the hardcoded constants here). Counter 0 adds nothing. */
    base[0] = ns_vreg0[0];
    base[1] = ns_vreg0[1];
    base[2] = ns_vreg0[2];
    base[3] = ns_vreg0[3];
    for (b = 1; b < 4; b++) {
        neon_block(load_le64(&x9[b * 16]), load_le64(&x9[b * 16 + 8]),
                   BRIDGE_VREG1, BRIDGE_VREG3, BRIDGE_VREG2, &base[b * 4]);
    }

    /* Normal rounds: ro[10+k] = RoundC(IV, base with counter k in hidden[5]). */
    for (k = 0; k <= 8; k++) {
        uint32_t h[16];
        uint32_t st[4];
        memcpy(h, base, sizeof h);
        h[5] += (uint32_t)k << 24;
        memcpy(st, NORMAL_ROUND_IV, sizeof st);
        roundc_md5_plain(st, h);
        memcpy(ro[10 + k], st, sizeof st);
    }
    memcpy(ro[9], NORMAL_ROUND_IV, sizeof ro[9]);
    for (k = 0; k < 8; k++) {
        memcpy(ro[k], ro[11 + k], sizeof ro[k]);
    }

    /* mixTable = BE(ro[10..18]). */
    for (b = 0; b < 9; b++) {
        be_round_output(ro[10 + b], &mix_table[b * 16]);
    }

    /* Round 8: SPN#1 -> R8 hidden words -> RoundC from round-8 IV. */
    spn1(ro, spn1_out);
    {
        uint8_t staging[64], d0[16];
        uint32_t h[16], st[4];
        bswap_words16(spn1_out, d0);
        memcpy(&staging[0], d0, 16);
        memcpy(&staging[16], R8_SUFFIX, 48);
        hidden_from_staging(staging, h);
        memcpy(st, ROUND8_INITIAL_STATE, sizeof st);
        roundc_md5_plain(st, h);
        memcpy(ro[8], st, sizeof st);
    }

    /* Round 19: TailInput -> TailSPN -> R19 staging -> RoundC from round-8 IV. */
    tail_input(ro, tail_in);
    tail_spn(tail_in, mix_table, tail_out);
    {
        uint8_t staging[64], d1[16];
        uint32_t h[16], st[4];
        for (w = 0; w < 4; w++) {
            store_le32(&staging[w * 4], ro[8][w]);
        }
        bswap_words16(tail_out, d1);
        memcpy(&staging[16], d1, 16);
        memcpy(&staging[32], MD_PAD_LEN, 32);
        hidden_from_staging(staging, h);
        memcpy(st, ROUND8_INITIAL_STATE, sizeof st);
        roundc_md5_plain(st, h);
        memcpy(ro[19], st, sizeof st);
    }

    /* span7[0:4] = tailOut[0:4]; span7[4:20] = BE(ro[19]). */
    memcpy(&out[0], tail_out, 4);
    for (w = 0; w < 4; w++) {
        store_be32(&out[4 + w * 4], ro[19][w]);
    }
}

/* ===================================================================== */
/* Constants: frozen local SAP, m3 prefix, bridge x9 tail                */
/* ===================================================================== */

static const uint8_t BRIDGE_X9_TAIL[44] = {
    0xee, 0xd8, 0x57, 0x00, 0xcf, 0xfb, 0xde, 0xcb, 0xa2, 0x27, 0x1c, 0x59,
    0x89, 0xb0, 0xbe, 0xcf, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x03, 0x20, 0x00, 0x00, 0x00, 0x00,
};

const uint8_t fp_frozen_local_sap[128] = {
    0x00, 0x01, 0xe4, 0xe3, 0xdd, 0x68, 0x82, 0x93, 0xe6, 0xfa, 0x66, 0xb9, 0x5b, 0xa4, 0x17, 0x68,
    0xe5, 0x87, 0xc6, 0x5f, 0x75, 0x02, 0x18, 0xff, 0x1b, 0xe2, 0x15, 0x43, 0xd5, 0x73, 0xce, 0xfb,
    0x08, 0x7b, 0xd3, 0x6e, 0x0c, 0x63, 0x63, 0xc3, 0xc8, 0x24, 0x2f, 0x4a, 0xbc, 0xfa, 0x6d, 0x66,
    0x0b, 0x80, 0x10, 0x32, 0x01, 0x54, 0x05, 0xeb, 0x4a, 0xb0, 0x4d, 0xda, 0x7a, 0xef, 0xf3, 0x8f,
    0xfb, 0x36, 0xf4, 0xcf, 0xa4, 0x8f, 0x0b, 0x5d, 0x92, 0xae, 0x36, 0x3f, 0x68, 0xb4, 0x59, 0x25,
    0xbb, 0xe6, 0x41, 0x3a, 0xb6, 0xbd, 0xc4, 0x96, 0x8f, 0x54, 0x8d, 0x21, 0xe6, 0x7d, 0x20, 0xf1,
    0x91, 0x2b, 0x68, 0x20, 0xe5, 0x3f, 0x10, 0x13, 0xcd, 0xe2, 0x9d, 0xf7, 0x35, 0x0a, 0x9b, 0x9f,
    0xa7, 0xc5, 0x13, 0x20, 0xae, 0xa6, 0x2d, 0x29, 0x49, 0x78, 0x6c, 0x87, 0x64, 0x2e, 0x34, 0xba,
};

const uint8_t fp_m3_prefix[144] = {
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x98, 0x03, 0x8f, 0x1a, 0x9c,
    0x99, 0x1e, 0xa2, 0x2c, 0x51, 0x1e, 0x45, 0xba, 0x97, 0xf1, 0xaf, 0x8d, 0xfb, 0x0f, 0x86, 0xf5,
    0x50, 0xc5, 0x44, 0x86, 0xfe, 0x6b, 0x3a, 0xb2, 0x33, 0xda, 0x43, 0x1e, 0xf8, 0xe5, 0xfc, 0x11,
    0x56, 0xdb, 0xa3, 0x21, 0xff, 0xfe, 0xab, 0xb1, 0xb3, 0x92, 0xb0, 0x9d, 0x22, 0x7e, 0x88, 0xc7,
    0x12, 0x20, 0x28, 0x66, 0xeb, 0x7b, 0xbf, 0x31, 0x00, 0x15, 0xaa, 0x1d, 0x19, 0xa5, 0xdf, 0x36,
    0xd5, 0xdf, 0xd8, 0xd3, 0xca, 0x16, 0x39, 0xb3, 0x76, 0xea, 0xec, 0xe9, 0x46, 0xed, 0xfe, 0x8b,
    0x7a, 0x66, 0xcd, 0x30, 0x2d, 0x04, 0xaa, 0xc3, 0xc1, 0x25, 0x17, 0x14, 0x01, 0x9b, 0xd5, 0xf2,
    0xd4, 0x9b, 0x54, 0x3e, 0x11, 0xee, 0xd1, 0x64, 0x62, 0x91, 0xec, 0x8e, 0xfd, 0x96, 0xb6, 0x91,
    0x01, 0xb8, 0x49, 0xfd, 0x93, 0xa0, 0x28, 0x60, 0xd1, 0xa0, 0xdf, 0xf5, 0xcd, 0x44, 0x14, 0xaa,
};

/* ===================================================================== */
/* exchange + framing                                                    */
/* ===================================================================== */

static void x9_from_head(const uint8_t head[20], uint8_t x9[64])
{
    memcpy(&x9[0], head, 20);
    memcpy(&x9[20], BRIDGE_X9_TAIL, 44);
}

void fp_exchange_blobless(const uint8_t payload[128], uint8_t out[20])
{
    uint8_t gp[128], head[20], x9[64];
    fp_gp_buffer(payload, gp);
    fp_bridge_x9_head_for_sap(fp_frozen_local_sap, gp, head);
    x9_from_head(head, x9);
    fp_phase2_from_x9(x9, out);
}

void fp_build_m1(uint8_t capabilities, uint8_t m1[FP_M1_LEN])
{
    static const uint8_t head[12] =
        {0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04};
    memcpy(m1, head, 12);
    m1[12] = 0x02;
    m1[13] = 0x00;
    m1[14] = capabilities;
    m1[15] = 0xbb;
}

int fp_parse_m2(const uint8_t *m2, size_t len, uint8_t challenge[128], int *mode)
{
    if (len != FP_M2_LEN) {
        return FP_ERR_LEN;
    }
    if (memcmp(m2, "FPLY", 4) != 0) {
        return FP_ERR_FRAMING;
    }
    /* Version must be 03 01 (FairPlay SAP v3). A receiver answers m2 with
     * version 02 only when the sender failed to select v3 on /fp-setup via the
     * "X-Apple-ET: 32" request header -- that is a transport bug, not a v2
     * device, so reject it here rather than answer with the wrong scheme. */
    if (m2[4] != 3 || m2[5] != 1 || m2[6] != 2 || m2[7] != 0) {
        return FP_ERR_FRAMING;
    }
    if (load_be32(&m2[8]) != 130) {
        return FP_ERR_FRAMING;
    }
    if (m2[12] != 2) {
        return FP_ERR_FRAMING;
    }
    if (m2[13] != FP_SUPPORTED_MODE) {
        if (mode) {
            *mode = m2[13];
        }
        return FP_ERR_MODE;
    }
    memcpy(challenge, &m2[14], 128);
    return FP_OK;
}

int fp_m3_frozen(const uint8_t *m2, size_t len, uint8_t m3[FP_M3_LEN], int *mode)
{
    uint8_t challenge[128], resp[20];
    int rc = fp_parse_m2(m2, len, challenge, mode);
    if (rc != FP_OK) {
        return rc;
    }
    fp_exchange_blobless(challenge, resp);
    memcpy(&m3[0], fp_m3_prefix, 144);
    memcpy(&m3[144], resp, 20);
    return FP_OK;
}

void fp_make_local_sap(const uint8_t entropy126[126], uint8_t local_sap[128])
{
    local_sap[0] = 0x00;
    local_sap[1] = 0x01;
    memcpy(&local_sap[2], entropy126, 126);
}

int fp_m3_session(const uint8_t *m2, size_t len, const uint8_t local_sap[128],
                  uint8_t m3[FP_M3_LEN], int *mode)
{
    uint8_t challenge[128], gp[128], head[20], x9[64], resp[20], body[128];
    int rc = fp_parse_m2(m2, len, challenge, mode);
    if (rc != FP_OK) {
        return rc;
    }
    fp_encrypt_body_mode3(local_sap, body);

    fp_gp_buffer(challenge, gp);
    fp_bridge_x9_head_for_sap(local_sap, gp, head);
    x9_from_head(head, x9);
    fp_phase2_from_x9(x9, resp);

    memcpy(&m3[0], "FPLY", 4);
    m3[4] = 3; m3[5] = 1; m3[6] = 3; m3[7] = 0;
    m3[8] = 0; m3[9] = 0; m3[10] = 0; m3[11] = 152;
    m3[12] = FP_SUPPORTED_MODE;
    m3[13] = 0x8f; m3[14] = 0x1a; m3[15] = 0x9c;
    memcpy(&m3[16], body, 128);
    memcpy(&m3[144], resp, 20);
    return FP_OK;
}

/* ===================================================================== */
/* m3 message body cipher (fpsapcore/message_encrypt.go)                 */
/* ===================================================================== */

static const uint8_t MSG_IV_MODE3[16] = {
    0x27, 0x07, 0x8b, 0x21, 0x23, 0x36, 0x1e, 0x7a, 0xdc, 0x9d, 0x0b, 0x11, 0x53, 0x54, 0x69, 0x0d};
static const uint8_t MSG_ROUND_KEY0[16] = {
    0xd3, 0x0d, 0xfd, 0xb5, 0x63, 0xde, 0xf7, 0x2b, 0x01, 0x2e, 0xad, 0x72, 0x88, 0x4d, 0xca, 0x25};
static const uint8_t MSG_ROUND_KEY10[16] = {
    0xcd, 0x5e, 0xcf, 0x47, 0xe9, 0xaf, 0x28, 0x9b, 0x51, 0x18, 0x8f, 0x68, 0xd0, 0x85, 0xeb, 0x69};
static const uint8_t MSG_MIDDLE_KEYS[9][16] = {
    {0xf6, 0xa2, 0x23, 0xb4, 0xf0, 0x1d, 0x8a, 0x79, 0x27, 0xa7, 0xc9, 0x65, 0xde, 0x55, 0x4d, 0xe0},
    {0x0c, 0xd1, 0x51, 0x5d, 0x43, 0x24, 0x6c, 0x87, 0xfc, 0x2f, 0x49, 0x43, 0x64, 0xa4, 0xcf, 0xbc},
    {0xd6, 0x6e, 0x3b, 0xdd, 0x6c, 0x7f, 0x1b, 0x81, 0x1f, 0x90, 0x29, 0x19, 0x84, 0xb5, 0xea, 0xee},
    {0x53, 0x0d, 0x7a, 0xe8, 0x5b, 0x30, 0x40, 0x56, 0x9f, 0x13, 0x13, 0x0f, 0x18, 0xfb, 0xb1, 0xe5},
    {0x07, 0x84, 0xc4, 0x7a, 0x9f, 0xe1, 0x0f, 0x3d, 0x5e, 0xa5, 0x43, 0x2e, 0xcd, 0xd9, 0xf5, 0x85},
    {0xb9, 0xb0, 0x36, 0x8e, 0xb7, 0xd1, 0x34, 0xd9, 0x0e, 0xbd, 0x1b, 0x94, 0xb2, 0x55, 0xa4, 0xfb},
    {0xb2, 0xa4, 0x35, 0x25, 0x34, 0x06, 0x6f, 0xde, 0xc1, 0xce, 0x38, 0xdb, 0x3d, 0x8c, 0x3b, 0x85},
    {0x0b, 0x31, 0x7a, 0x94, 0x25, 0x20, 0x62, 0x2d, 0x89, 0x57, 0x8e, 0x9f, 0xe5, 0xa1, 0x3f, 0xc3},
    {0xbd, 0xf5, 0x69, 0xe6, 0xbe, 0xfc, 0x1d, 0x2f, 0xc0, 0x8b, 0xaf, 0x73, 0x3f, 0x1d, 0x17, 0x6a},
};
static const uint8_t FORWARD_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t product = 0;
    while (b) {
        if (b & 1) {
            product ^= a;
        }
        {
            uint8_t high = (uint8_t)(a & 0x80);
            a = (uint8_t)(a << 1);
            if (high) {
                a ^= 0x1b;
            }
        }
        b >>= 1;
    }
    return product;
}

static void msg_xor_key(uint8_t state[16], const uint8_t key[16])
{
    int i;
    for (i = 0; i < 16; i++) {
        state[i] ^= key[i];
    }
}

static void msg_sub_bytes(uint8_t state[16])
{
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = FORWARD_SBOX[state[i]];
    }
}

static void msg_shift_rows(uint8_t state[16])
{
    uint8_t prev[16];
    int row, column;
    memcpy(prev, state, 16);
    for (row = 0; row < 4; row++) {
        for (column = 0; column < 4; column++) {
            state[4 * column + row] = prev[4 * ((column + row) & 3) + row];
        }
    }
}

static void msg_mix_columns(uint8_t state[16])
{
    int column;
    for (column = 0; column < 4; column++) {
        int o = column * 4;
        uint8_t a = state[o], b = state[o + 1], c = state[o + 2], d = state[o + 3];
        state[o] = (uint8_t)(gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d);
        state[o + 1] = (uint8_t)(a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d);
        state[o + 2] = (uint8_t)(a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3));
        state[o + 3] = (uint8_t)(gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2));
    }
}

static void msg_encrypt_block(uint8_t state[16])
{
    int round;
    msg_xor_key(state, MSG_ROUND_KEY0);
    msg_sub_bytes(state);
    msg_shift_rows(state);
    for (round = 0; round < 9; round++) {
        msg_mix_columns(state);
        msg_xor_key(state, MSG_MIDDLE_KEYS[round]);
        msg_sub_bytes(state);
        msg_shift_rows(state);
    }
    msg_xor_key(state, MSG_ROUND_KEY10);
}

void fp_encrypt_body_mode3(const uint8_t plaintext[128], uint8_t out[128])
{
    uint8_t chain[16];
    int block, i;
    memcpy(chain, MSG_IV_MODE3, 16);
    for (block = 0; block < 8; block++) {
        int start = block * 16;
        uint8_t state[16];
        for (i = 0; i < 16; i++) {
            state[i] = (uint8_t)(plaintext[start + i] ^ chain[i]);
        }
        msg_encrypt_block(state);
        memcpy(&out[start], state, 16);
        memcpy(chain, &out[start], 16);
    }
}

/* ===================================================================== */
/* FairPlay audio-key wrapping support (sender side).                    */
/*                                                                       */
/* The AirPlay 2 buffered stream key is FairPlay-wrapped: the sender     */
/* generates a random 16-byte raw key, derives a wrapping key + MAC key  */
/* from the two session SAPs, and emits a 72-byte FPLY "ekey" record in  */
/* SETUP. These functions provide the FairPlay-specific halves (the      */
/* m2-body decrypt, the wrapping-key KDF, exposed via fp_key_material);   */
/* the host assembles the ekey and derives the stream key with its own   */
/* standard AES/HMAC/SHA-512. Matches doubletake 8ccea5f byte-for-byte.  */
/* ===================================================================== */

/* Inverse of the mode-3 message block cipher (msg_encrypt_block). */
static void msg_inv_shift_rows(uint8_t state[16])
{
    uint8_t prev[16];
    int row, column;
    memcpy(prev, state, 16);
    for (row = 0; row < 4; row++) {
        for (column = 0; column < 4; column++) {
            state[4 * column + row] = prev[4 * (((column - row) + 4) & 3) + row];
        }
    }
}

static void msg_inv_mix_columns(uint8_t state[16])
{
    int column;
    for (column = 0; column < 4; column++) {
        int o = column * 4;
        uint8_t a = state[o], b = state[o + 1], c = state[o + 2], d = state[o + 3];
        state[o]     = (uint8_t)(gf_mul(a, 14) ^ gf_mul(b, 11) ^ gf_mul(c, 13) ^ gf_mul(d, 9));
        state[o + 1] = (uint8_t)(gf_mul(a, 9)  ^ gf_mul(b, 14) ^ gf_mul(c, 11) ^ gf_mul(d, 13));
        state[o + 2] = (uint8_t)(gf_mul(a, 13) ^ gf_mul(b, 9)  ^ gf_mul(c, 14) ^ gf_mul(d, 11));
        state[o + 3] = (uint8_t)(gf_mul(a, 11) ^ gf_mul(b, 13) ^ gf_mul(c, 9)  ^ gf_mul(d, 14));
    }
}

static void msg_decrypt_block(uint8_t state[16], const uint8_t inv_sbox[256])
{
    int round, i;
    msg_xor_key(state, MSG_ROUND_KEY10);
    for (round = 9; round >= 1; round--) {
        msg_inv_shift_rows(state);
        for (i = 0; i < 16; i++) {
            state[i] = inv_sbox[state[i]];
        }
        msg_xor_key(state, MSG_MIDDLE_KEYS[round - 1]);
        msg_inv_mix_columns(state);
    }
    msg_inv_shift_rows(state);
    for (i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
    msg_xor_key(state, MSG_ROUND_KEY0);
}

/* CBC decrypt of a 128-byte mode-3 FairPlay message body (inverse of
 * fp_encrypt_body_mode3). */
void fp_decrypt_body_mode3(const uint8_t in[128], uint8_t out[128])
{
    uint8_t inv_sbox[256];
    const uint8_t *chain;
    int block, i;
    for (i = 0; i < 256; i++) {
        inv_sbox[FORWARD_SBOX[i]] = (uint8_t)i;
    }
    chain = MSG_IV_MODE3;
    for (block = 0; block < 8; block++) {
        int start = block * 16;
        uint8_t state[16];
        memcpy(state, &in[start], 16);
        msg_decrypt_block(state, inv_sbox);
        for (i = 0; i < 16; i++) {
            out[start + i] = (uint8_t)(state[i] ^ chain[i]);
        }
        chain = &in[start];
    }
}

/* fairplayKDFPrefix / fairplayKDFSuffix (doubletake fairplay_crypto.go). */
static const uint8_t FP_KDF_PREFIX[17] = {
    0xfa, 0x9c, 0xad, 0x4d, 0x4b, 0x68, 0x26, 0x8c,
    0x7f, 0xf3, 0x88, 0x99, 0xde, 0x92, 0x2e, 0x95, 0x1e,
};
static const uint8_t FP_KDF_SUFFIX[17] = {
    0xec, 0x4e, 0x27, 0x5e, 0xfd, 0xf2, 0xe8, 0x30,
    0x97, 0xae, 0x70, 0xfb, 0xe0, 0x00, 0x3f, 0x1c, 0x39,
};

/* The 16-byte AES wrapping key: a modified-MD5/SAP-hash KDF over
 *   prefix || sender_sap || receiver_sap || suffix
 * padded to 320 bytes (0x80 then LE64 bit length). Message words are loaded
 * big-endian, the init IV is bridge_md5_init (== fairplayInitialSessionKey
 * loaded little-endian), the per-block SAP hash is combined little-endian,
 * and the result is emitted big-endian -- matching deriveFairPlayWrappingKey. */
void fp_wrapping_key(const uint8_t sender_sap[128],
                     const uint8_t receiver_sap[128],
                     uint8_t out_key[16])
{
    uint8_t material[320];
    uint32_t state[4];
    uint64_t bitlen;
    int off, blk, w, i;

    memset(material, 0, sizeof material);
    off = 0;
    memcpy(&material[off], FP_KDF_PREFIX, 17); off += 17;
    memcpy(&material[off], sender_sap, 128);   off += 128;
    memcpy(&material[off], receiver_sap, 128); off += 128;
    memcpy(&material[off], FP_KDF_SUFFIX, 17); off += 17;   /* off == 290 */
    material[off] = 0x80;
    bitlen = (uint64_t)off * 8u;                            /* 290 * 8 == 2320 */
    for (i = 0; i < 8; i++) {
        material[320 - 8 + i] = (uint8_t)(bitlen >> (8 * i));
    }

    bridge_md5_init(state);
    for (blk = 0; blk < 5; blk++) {
        const uint8_t *block = &material[blk * 64];
        uint32_t msg[16];
        uint32_t tmp[4];
        uint8_t hashed[16];
        /* doubletake's deriveFairPlayWrappingKey drives fairplayMD5Compress with
         * the STANDARD RFC1321 MD5 constant table (fairplayMD5Constant ==
         * STD_MD5_K), i.e. additive offset 0, uniformly on every block. The
         * BRIDGE_HASH*_OFFSET macros belong to the auth-path hashes, not this
         * KDF. */
        uint32_t offset = 0u;
        for (w = 0; w < 16; w++) {
            msg[w] = load_be32(&block[w * 4]);
        }
        tmp[0] = state[0]; tmp[1] = state[1]; tmp[2] = state[2]; tmp[3] = state[3];
        bridge_md5_compress(tmp, msg, offset, BRIDGE_MUTATION_KDF);
        fp_sap_hash(block, hashed);
        for (w = 0; w < 4; w++) {
            state[w] = tmp[w] + load_le32(&hashed[w * 4]);
        }
    }
    for (w = 0; w < 4; w++) {
        store_be32(&out_key[w * 4], state[w]);
    }
}

/* Parse the receiver's m2 and produce the two FairPlay key-derivation halves
 * the host needs to wrap the stream audio key:
 *   wrap_key[16] = fp_wrapping_key(local_sap, decrypt(m2 body))
 *   mac_key[20]  = fp_sap_descriptor_for_sap(local_sap, decrypt(m2 body))
 * sender_sap == local_sap (the SAP the host passed to fp_m3_session), so the
 * only decryption needed is the m2 body. Returns FP_OK or a negative FP_ERR_*. */
int fp_key_material(const uint8_t *m2, size_t m2_len,
                    const uint8_t local_sap[128],
                    uint8_t wrap_key[16], uint8_t mac_key[20], int *mode)
{
    uint8_t raw_challenge[128], receiver_sap[128];
    int rc = fp_parse_m2(m2, m2_len, raw_challenge, mode);
    if (rc != FP_OK) {
        return rc;
    }
    fp_decrypt_body_mode3(raw_challenge, receiver_sap);
    fp_wrapping_key(local_sap, receiver_sap, wrap_key);
    fp_sap_descriptor_for_sap(local_sap, receiver_sap, mac_key);
    return FP_OK;
}
