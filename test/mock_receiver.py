#!/usr/bin/env python3
"""A throwaway mock AirPlay fp-setup receiver, for exercising the C sender's
RTSP transport without a real device. It does NOT validate FairPlay crypto --
it only checks the framing and returns a well-formed m2 then m4."""
import socket, sys, struct

def read_request(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, None, None
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    reqline = lines[0]
    clen = 0
    for ln in lines[1:]:
        if ln.lower().startswith(b"content-length:"):
            clen = int(ln.split(b":", 1)[1].strip())
    body = rest
    while len(body) < clen:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk
    return reqline, head, body[:clen]

def respond(conn, code, reason, body=b""):
    hdr = (b"RTSP/1.0 %d %s\r\n" % (code, reason.encode()))
    hdr += b"CSeq: 1\r\n"
    hdr += b"Content-Length: %d\r\n\r\n" % len(body)
    conn.sendall(hdr + body)

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    print("mock receiver on 127.0.0.1:%d" % port, flush=True)
    conn, _ = s.accept()

    # ---- m1 -> m2 ----
    reqline, _, m1 = read_request(conn)
    assert m1 is not None and len(m1) == 16, "m1 len %r" % (len(m1) if m1 else None)
    assert m1[:4] == b"FPLY" and m1[6] == 1, "bad m1 framing"
    print("got m1:", m1.hex(), flush=True)
    # build a 142-byte m2: FPLY 0301 02 00, len=130, marker 02, mode 03, 128B challenge
    challenge = bytes((i * 7 + 3) & 0xff for i in range(128))
    m2 = b"FPLY" + bytes([3,1,2,0]) + struct.pack(">I", 130) + bytes([2, 3]) + challenge
    assert len(m2) == 142
    respond(conn, 200, "OK", m2)
    print("sent m2 (142B)", flush=True)

    # ---- m3 -> m4 ----
    reqline, _, m3 = read_request(conn)
    assert m3 is not None and len(m3) == 164, "m3 len %r" % (len(m3) if m3 else None)
    assert m3[:4] == b"FPLY" and m3[6] == 3, "bad m3 framing"
    assert m3[12] == 3, "m3 mode byte"
    print("got m3:", m3.hex()[:32], "... (164B, mode %d)" % m3[12], flush=True)
    # a real HomePod m4 is 32 bytes: FPLY 0301 04 00 len=20 then 20 bytes
    m4 = b"FPLY" + bytes([3,1,4,0]) + struct.pack(">I", 20) + bytes(20)
    assert len(m4) == 32
    respond(conn, 200, "OK", m4)
    print("sent m4 (32B)", flush=True)
    conn.close()

main()
