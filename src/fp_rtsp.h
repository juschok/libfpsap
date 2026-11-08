/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * fp_rtsp.h -- minimal RTSP-over-TCP transport for the FairPlay SAP /fp-setup
 * exchange, plus the end-to-end handshake driver.
 *
 * AirPlay 2 receivers speak an HTTP-shaped RTSP on port 7000. The FairPlay SAP
 * handshake is two POST /fp-setup requests on the SAME connection, carrying the
 * X-Apple-ET: 32 header that selects FairPlay SAP v3:
 *
 *     sender  --POST /fp-setup (m1, 16B)-->  receiver
 *     sender  <--200, body = m2 (142B)----   receiver
 *     sender  --POST /fp-setup (m3, 164B)-->  receiver
 *     sender  <--200, body = m4 (~32B)-----   receiver   (or 403/466 on reject)
 *
 * NOTE ON ENCRYPTION: on most real AirPlay 2 receivers /fp-setup rides inside a
 * channel already set up by pair-setup/pair-verify, and the byte stream is
 * ChaCha20-Poly1305 framed once pairing completes. This transport speaks
 * cleartext RTSP: it works where fp-setup is accepted unencrypted (the
 * "permissive receiver" case this project targets), or when you hand it a fd
 * that is already the post-pairing encrypted stream. Pairing itself (SRP /
 * curve25519 / HKDF) is out of scope here -- you bring the live socket.
 */
#ifndef FP_RTSP_H
#define FP_RTSP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int fd;       /* connected TCP socket; -1 when closed            */
    int cseq;     /* RTSP CSeq counter, incremented per request      */
    char host[256];
} fp_conn;

/* Connect to host:port over TCP. port may be NULL ("7000" assumed).
 * Returns 0 on success; negative on error (errno is set). */
int fp_dial(fp_conn *c, const char *host, const char *port);

/* Wrap an already-connected socket fd (e.g. a post-pairing encrypted stream).
 * host is used only for the Host: header. */
void fp_conn_wrap(fp_conn *c, int fd, const char *host);

void fp_conn_close(fp_conn *c);

/* Send one RTSP request and read one response.
 *   extra / nextra : additional raw header lines, e.g. "X-Apple-ET: 32".
 *   status_out     : receives the numeric status code (may be NULL).
 *   resp_body      : buffer for the response body (may be NULL to discard).
 *   resp_len       : receives the body length actually read (may be NULL).
 * Returns 0 on a well-formed exchange (any status code), negative on a
 * transport/parse error. */
int fp_rtsp_do(fp_conn *c, const char *method, const char *path,
               const char *content_type,
               const uint8_t *body, size_t body_len,
               const char *const *extra, int nextra,
               int *status_out,
               uint8_t *resp_body, size_t resp_cap, size_t *resp_len);

/* Run the whole FairPlay SAP handshake on c, using local_sap (build it with
 * fp_make_local_sap). On success returns 0, writes the receiver's m4 into
 * m4_out, and sets *m4_len. The m2 and m3 that crossed the wire are copied into
 * m2_out[142] and m3_out[164] when those pointers are non-NULL.
 *
 * Return codes:
 *    0  accepted  (m3 got a 2xx; m4 captured)
 *   -1  transport/parse error
 *   -2  m1 did not return a 142-byte m2
 *   -3  m2 rejected (bad framing or non-mode-3)
 *   -4  m3 was rejected by the receiver (non-2xx: 403 / 466 key-management)
 */
int fp_handshake(fp_conn *c, const uint8_t local_sap[128],
                 uint8_t *m2_out, uint8_t *m3_out,
                 uint8_t *m4_out, size_t m4_cap, size_t *m4_len,
                 int *m3_status_out);

#ifdef __cplusplus
}
#endif

#endif
