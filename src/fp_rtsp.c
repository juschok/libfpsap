/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * fp_rtsp.c -- RTSP transport + handshake driver. See fp_rtsp.h.
 */
#define _POSIX_C_SOURCE 200809L

#include "fp_rtsp.h"
#include "fp_crypto.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define FP_RTSP_ET_HEADER "X-Apple-ET: 32"
#define FP_RTSP_UA "AirPlay/366.0"
#define FP_RTSP_CLIENT_ID "5FA1E4E01234ABCD"
#define FP_RTSP_MAXBODY (1u << 20)

/* ---- socket helpers --------------------------------------------------- */

static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int fp_dial(fp_conn *c, const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL, *ai;
    int fd = -1, rc;
    if (!port) {
        port = "7000";
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        return -1;
    }
    c->fd = fd;
    c->cseq = 0;
    snprintf(c->host, sizeof c->host, "%s", host);
    return 0;
}

void fp_conn_wrap(fp_conn *c, int fd, const char *host)
{
    c->fd = fd;
    c->cseq = 0;
    snprintf(c->host, sizeof c->host, "%s", host ? host : "");
}

void fp_conn_close(fp_conn *c)
{
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* ---- response reader -------------------------------------------------- */

/* A tiny buffered reader: we read in chunks into rb[], find the end of the
 * header block (CRLFCRLF), parse the status code and Content-Length, then make
 * sure the body is fully present. */
int fp_rtsp_do(fp_conn *c, const char *method, const char *path,
               const char *content_type,
               const uint8_t *body, size_t body_len,
               const char *const *extra, int nextra,
               int *status_out,
               uint8_t *resp_body, size_t resp_cap, size_t *resp_len)
{
    char hdr[1024];
    int n, i;
    uint8_t rb[8192];
    size_t have = 0;
    size_t hdr_end = 0;
    int status = 0;
    long clen = -1;

    c->cseq++;
    n = snprintf(hdr, sizeof hdr,
                 "%s %s RTSP/1.0\r\n"
                 "CSeq: %d\r\n"
                 "Host: %s\r\n"
                 "User-Agent: %s\r\n"
                 "Connection: keep-alive\r\n"
                 "Client-Instance: %s\r\n"
                 "DACP-ID: %s\r\n",
                 method, path, c->cseq, c->host,
                 FP_RTSP_UA, FP_RTSP_CLIENT_ID, FP_RTSP_CLIENT_ID);
    if (n < 0 || (size_t)n >= sizeof hdr) {
        return -1;
    }
    for (i = 0; i < nextra; i++) {
        int m = snprintf(hdr + n, sizeof hdr - (size_t)n, "%s\r\n", extra[i]);
        if (m < 0 || (size_t)(n + m) >= sizeof hdr) {
            return -1;
        }
        n += m;
    }
    if (body_len > 0 || content_type) {
        int m = snprintf(hdr + n, sizeof hdr - (size_t)n, "Content-Type: %s\r\n",
                         content_type ? content_type : "application/octet-stream");
        if (m < 0 || (size_t)(n + m) >= sizeof hdr) {
            return -1;
        }
        n += m;
    }
    {
        int m = snprintf(hdr + n, sizeof hdr - (size_t)n,
                         "Content-Length: %zu\r\n\r\n", body_len);
        if (m < 0 || (size_t)(n + m) >= sizeof hdr) {
            return -1;
        }
        n += m;
    }

    if (write_all(c->fd, (const uint8_t *)hdr, (size_t)n) != 0) {
        return -1;
    }
    if (body_len > 0 && write_all(c->fd, body, body_len) != 0) {
        return -1;
    }

    /* Read until we have the full header block. */
    for (;;) {
        ssize_t r;
        size_t k;
        if (have >= sizeof rb) {
            return -1; /* header too large */
        }
        r = read(c->fd, rb + have, sizeof rb - have);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            return -1; /* closed before headers complete */
        }
        have += (size_t)r;
        for (k = 3; k < have; k++) {
            if (rb[k - 3] == '\r' && rb[k - 2] == '\n' &&
                rb[k - 1] == '\r' && rb[k] == '\n') {
                hdr_end = k + 1;
                break;
            }
        }
        if (hdr_end) {
            break;
        }
    }

    /* Parse the status line + Content-Length out of rb[0..hdr_end). */
    {
        char *line, *save = NULL;
        char tmp[8192];
        size_t cp = hdr_end < sizeof tmp ? hdr_end : sizeof tmp - 1;
        memcpy(tmp, rb, cp);
        tmp[cp] = '\0';
        line = strtok_r(tmp, "\r\n", &save);
        if (line) {
            /* "RTSP/1.0 200 OK" */
            char *sp = strchr(line, ' ');
            if (sp) {
                status = (int)strtol(sp + 1, NULL, 10);
            }
        }
        for (line = strtok_r(NULL, "\r\n", &save); line;
             line = strtok_r(NULL, "\r\n", &save)) {
            if (strncasecmp(line, "Content-Length:", 15) == 0) {
                clen = strtol(line + 15, NULL, 10);
            }
        }
    }
    if (status == 0) {
        return -1;
    }
    if (clen < 0) {
        clen = 0;
    }
    if ((size_t)clen > FP_RTSP_MAXBODY) {
        return -1;
    }

    /* Ensure the full body is present (read more if needed). */
    {
        size_t body_have = have - hdr_end;
        size_t want = (size_t)clen;
        uint8_t *bodybuf = NULL;
        int rc = 0;

        if (resp_body && resp_cap > 0) {
            bodybuf = resp_body;
        }
        /* copy what we already have */
        if (bodybuf && body_have > 0) {
            size_t cp = body_have < resp_cap ? body_have : resp_cap;
            memcpy(bodybuf, rb + hdr_end, cp);
        }
        while (body_have < want) {
            uint8_t chunk[4096];
            ssize_t r = read(c->fd, chunk, sizeof chunk);
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                rc = -1;
                break;
            }
            if (r == 0) {
                rc = -1;
                break;
            }
            if (bodybuf) {
                size_t pos = body_have;
                size_t cp = (size_t)r;
                if (pos < resp_cap) {
                    size_t room = resp_cap - pos;
                    memcpy(bodybuf + pos, chunk, cp < room ? cp : room);
                }
            }
            body_have += (size_t)r;
        }
        if (status_out) {
            *status_out = status;
        }
        if (resp_len) {
            *resp_len = want < resp_cap ? want : (resp_body ? resp_cap : want);
        }
        return rc;
    }
}

/* ---- the handshake ---------------------------------------------------- */

int fp_handshake(fp_conn *c, const uint8_t local_sap[128],
                 uint8_t *m2_out, uint8_t *m3_out,
                 uint8_t *m4_out, size_t m4_cap, size_t *m4_len,
                 int *m3_status_out)
{
    const char *et[1] = {FP_RTSP_ET_HEADER};
    uint8_t m1[FP_M1_LEN];
    uint8_t m2[FP_M2_LEN];
    uint8_t m3[FP_M3_LEN];
    size_t rlen = 0;
    int status = 0, rc;

    /* --- m1 -> m2 --- */
    fp_build_m1(3, m1);
    rc = fp_rtsp_do(c, "POST", "/fp-setup", "application/octet-stream",
                    m1, sizeof m1, et, 1, &status, m2, sizeof m2, &rlen);
    if (rc != 0) {
        return -1;
    }
    if (status < 200 || status >= 300 || rlen != FP_M2_LEN) {
        return -2;
    }
    if (m2_out) {
        memcpy(m2_out, m2, FP_M2_LEN);
    }

    /* --- compute m3 (session-aware) --- */
    {
        int mode = 0;
        rc = fp_m3_session(m2, FP_M2_LEN, local_sap, m3, &mode);
        if (rc != FP_OK) {
            return -3;
        }
    }
    if (m3_out) {
        memcpy(m3_out, m3, FP_M3_LEN);
    }

    /* --- m3 -> m4 --- */
    status = 0;
    rc = fp_rtsp_do(c, "POST", "/fp-setup", "application/octet-stream",
                    m3, sizeof m3, et, 1, &status, m4_out, m4_cap, m4_len);
    if (m3_status_out) {
        *m3_status_out = status;
    }
    if (rc != 0) {
        return -1;
    }
    if (status < 200 || status >= 300) {
        return -4; /* rejected: 403 Forbidden or 466 Key Management Error */
    }
    return 0;
}
