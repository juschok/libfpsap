/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Offline conformance test for the full C FairPlay SAP engine.
 *   cc -std=c99 fp_crypto.c fp_tables.c fairplay_sapcore.c fairplay_bridge.c \
 *      fp_test.c -o t && ./t ../vectors
 *
 * Verifies, with no device and no Go:
 *   - the 142 golden vectors (payload -> 20-byte response, the frozen path);
 *   - the m3 message-body cipher (encrypting the frozen SAP reproduces the
 *     constant m3 prefix body);
 *   - that a frozen-SAP session m3 equals the frozen replay m3 byte for byte.
 */
#include "fp_crypto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int parse_hex(const char *s, uint8_t *out, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            return 0;
        }
        out[i] = (uint8_t)v;
    }
    return 1;
}

static int run_golden(const char *dir)
{
    char path[1024];
    FILE *f;
    char line[1024];
    int pass = 0, fail = 0, lineno = 0;

    snprintf(path, sizeof path, "%s/golden_vectors.csv", dir);
    f = fopen(path, "r");
    if (!f) {
        printf("cannot open %s\n", path);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char *fields[4];
        int nf = 0;
        char *p = line, *start = line;
        lineno++;
        if (lineno == 1) {
            continue; /* header */
        }
        /* split on commas (payload/hash have no embedded commas) */
        for (; *p && nf < 4; p++) {
            if (*p == ',' || *p == '\n' || *p == '\r') {
                char c = *p;
                *p = '\0';
                fields[nf++] = start;
                start = p + 1;
                if (c == '\n' || c == '\r') {
                    break;
                }
            }
        }
        if (nf < 4) {
            continue;
        }
        {
            uint8_t payload[128], want[20], got[20];
            if (strlen(fields[2]) < 256 || strlen(fields[3]) < 40) {
                continue;
            }
            if (!parse_hex(fields[2], payload, 128) || !parse_hex(fields[3], want, 20)) {
                continue;
            }
            fp_exchange_blobless(payload, got);
            if (memcmp(got, want, 20) == 0) {
                pass++;
            } else {
                fail++;
                if (fail <= 3) {
                    int k;
                    printf("MISMATCH %s: got ", fields[0]);
                    for (k = 0; k < 20; k++) printf("%02x", got[k]);
                    printf(" want ");
                    for (k = 0; k < 20; k++) printf("%02x", want[k]);
                    printf("\n");
                }
            }
        }
    }
    fclose(f);
    printf("golden vectors: %d/%d\n", pass, pass + fail);
    return fail;
}

static int test_message_body(void)
{
    uint8_t body[128];
    extern const uint8_t fp_m3_prefix[144];
    fp_encrypt_body_mode3(fp_frozen_local_sap, body);
    if (memcmp(body, &fp_m3_prefix[16], 128) == 0) {
        printf("message body: OK (reproduces frozen m3 prefix body)\n");
        return 0;
    }
    printf("message body: FAIL\n");
    return 1;
}

static int test_session_matches_frozen(const char *dir)
{
    /* Build an m2 from a golden payload, compute both frozen and frozen-SAP
     * session m3, and check they match (body + response). */
    char path[1024];
    FILE *f;
    char line[1024];
    int lineno = 0, rc = 1;
    snprintf(path, sizeof path, "%s/golden_vectors.csv", dir);
    f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        lineno++;
        if (lineno != 2) {
            continue; /* first data row */
        }
        {
            char *c2 = strchr(line, ',');
            char *c3 = c2 ? strchr(c2 + 1, ',') : NULL;
            if (!c3) break;
            {
                uint8_t payload[128], m2[FP_M2_LEN], m3f[FP_M3_LEN], m3s[FP_M3_LEN];
                uint8_t sap[128];
                if (!parse_hex(c3 + 1, payload, 128)) break;
                /* frame the payload as an m2 */
                memcpy(m2, "FPLY", 4);
                m2[4] = 3; m2[5] = 1; m2[6] = 2; m2[7] = 0;
                m2[8] = 0; m2[9] = 0; m2[10] = 0; m2[11] = 130;
                m2[12] = 2; m2[13] = 3;
                memcpy(&m2[14], payload, 128);
                memcpy(sap, fp_frozen_local_sap, 128);
                if (fp_m3_frozen(m2, FP_M2_LEN, m3f, NULL) != FP_OK) break;
                if (fp_m3_session(m2, FP_M2_LEN, sap, m3s, NULL) != FP_OK) break;
                if (memcmp(m3f, m3s, FP_M3_LEN) == 0) {
                    printf("session==frozen (frozen SAP): OK\n");
                    rc = 0;
                } else {
                    printf("session==frozen (frozen SAP): FAIL\n");
                    rc = 1;
                }
            }
        }
        break;
    }
    fclose(f);
    return rc;
}

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : "../vectors";
    int fails = 0;
    int g = run_golden(dir);
    if (g < 0) return 2;
    fails += g;
    fails += test_message_body();
    fails += test_session_matches_frozen(dir);
    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("FAILURES: %d\n", fails);
    return 1;
}
