/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * fp_main.c -- a small driver for the FairPlay SAP handshake.
 *
 *   fpsap handshake <host> [port]   run the whole exchange over a live socket,
 *                                   print m2 / m3 / m4 and the verdict
 *   fpsap m1                        print the 16-byte m1 record (hex)
 *   fpsap exchange <payloadhex>     128-byte challenge -> 20-byte response
 *   fpsap m3 <m2hex>                142-byte m2 -> 164-byte session m3
 */
#include "fp_crypto.h"
#include "fp_rtsp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int read_entropy(uint8_t *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;
    if (!f) {
        return -1;
    }
    got = fread(buf, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

static void print_hex(const char *label, const uint8_t *b, size_t n)
{
    size_t i;
    if (label) {
        printf("%s", label);
    }
    for (i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static int from_hex(const char *s, uint8_t *out, size_t n)
{
    size_t i;
    if (strlen(s) < 2 * n) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int cmd_handshake(int argc, char **argv)
{
    fp_conn c;
    uint8_t entropy[126], sap[128];
    uint8_t m2[FP_M2_LEN], m3[FP_M3_LEN], m4[256];
    size_t m4_len = 0;
    int status = 0, rc;
    const char *host, *port;

    if (argc < 1) {
        fprintf(stderr, "usage: fpsap handshake <host> [port]\n");
        return 2;
    }
    host = argv[0];
    port = (argc >= 2) ? argv[1] : "7000";

    if (read_entropy(entropy, sizeof entropy) != 0) {
        fprintf(stderr, "fpsap: cannot read /dev/urandom\n");
        return 1;
    }
    fp_make_local_sap(entropy, sap);

    if (fp_dial(&c, host, port) != 0) {
        fprintf(stderr, "fpsap: cannot connect to %s:%s\n", host, port);
        return 1;
    }
    fprintf(stderr, "connected to %s:%s\n", host, port);

    rc = fp_handshake(&c, sap, m2, m3, m4, sizeof m4, &m4_len, &status);
    fp_conn_close(&c);

    switch (rc) {
    case 0:
        print_hex("m2  = ", m2, FP_M2_LEN);
        print_hex("m3  = ", m3, FP_M3_LEN);
        print_hex("m4  = ", m4, m4_len);
        fprintf(stderr, "ACCEPTED (m3 status %d, m4 is %zu bytes)\n", status, m4_len);
        return 0;
    case -2:
        fprintf(stderr, "fpsap: m1 did not yield a 142-byte m2\n");
        return 1;
    case -3:
        fprintf(stderr, "fpsap: m2 rejected (bad framing or non-mode-3)\n");
        return 1;
    case -4:
        print_hex("m2  = ", m2, FP_M2_LEN);
        print_hex("m3  = ", m3, FP_M3_LEN);
        fprintf(stderr, "REJECTED by receiver: m3 status %d "
                        "(403 = forbidden, 466 = key management / replay)\n", status);
        return 1;
    default:
        fprintf(stderr, "fpsap: transport error\n");
        return 1;
    }
}

static int cmd_m1(void)
{
    uint8_t m1[FP_M1_LEN];
    fp_build_m1(3, m1);
    print_hex(NULL, m1, FP_M1_LEN);
    return 0;
}

static int cmd_exchange(int argc, char **argv)
{
    uint8_t payload[128], resp[20];
    if (argc < 1 || from_hex(argv[0], payload, 128) != 0) {
        fprintf(stderr, "usage: fpsap exchange <256-hex-char payload>\n");
        return 2;
    }
    fp_exchange_blobless(payload, resp);
    print_hex(NULL, resp, 20);
    return 0;
}

static int cmd_m3(int argc, char **argv)
{
    uint8_t m2[FP_M2_LEN], m3[FP_M3_LEN], entropy[126], sap[128];
    int mode = 0, rc;
    if (argc < 1 || from_hex(argv[0], m2, FP_M2_LEN) != 0) {
        fprintf(stderr, "usage: fpsap m3 <284-hex-char m2>\n");
        return 2;
    }
    if (read_entropy(entropy, sizeof entropy) != 0) {
        fprintf(stderr, "fpsap: cannot read /dev/urandom\n");
        return 1;
    }
    fp_make_local_sap(entropy, sap);
    rc = fp_m3_session(m2, FP_M2_LEN, sap, m3, &mode);
    if (rc == FP_ERR_MODE) {
        fprintf(stderr, "fpsap: m2 selected mode %d; only mode 3 is answerable\n", mode);
        return 1;
    }
    if (rc != FP_OK) {
        fprintf(stderr, "fpsap: malformed m2 (rc %d)\n", rc);
        return 1;
    }
    print_hex(NULL, m3, FP_M3_LEN);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage:\n"
                "  fpsap handshake <host> [port]   full exchange over a socket\n"
                "  fpsap m1                        print m1 (hex)\n"
                "  fpsap exchange <payloadhex>     challenge -> 20-byte response\n"
                "  fpsap m3 <m2hex>                m2 -> session m3\n");
        return 2;
    }
    if (strcmp(argv[1], "handshake") == 0) {
        return cmd_handshake(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "m1") == 0) {
        return cmd_m1();
    }
    if (strcmp(argv[1], "exchange") == 0) {
        return cmd_exchange(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "m3") == 0) {
        return cmd_m3(argc - 2, argv + 2);
    }
    fprintf(stderr, "fpsap: unknown command %s\n", argv[1]);
    return 2;
}
