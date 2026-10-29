# The v1 nixosTest's service (nix/test-internal.nix): mutual TLS with hanko's X.509-SVID,
# authorising the peer on its SPIFFE ID, the single URI SAN (ADR 0004). hanko sends it nothing
# (ADR 0013): the server re-reads its files when one changed, checked before every handshake, so
# a new SVID or bundle is served without a reload or a restart.
#   serve PEER_ID            accept on :8443, answer "hello" to PEER_ID only
#   call PEER_ID ADDRESS     connect, require PEER_ID, print the server's serial and answer
import os
import socket
import ssl
import sys

DIR = "/var/lib/hanko/svc"
FILES = [f"{DIR}/{f}.pem" for f in ("svid", "key", "bundle")]


def stamp():
    """Inode and mtime of the files: hanko renames new files into place."""
    return [(s.st_ino, s.st_mtime_ns) for s in map(os.stat, FILES)]


def context(side):
    ctx = ssl.SSLContext(side)
    # An SVID has no DNS name: the peer's URI SAN is checked instead.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(f"{DIR}/svid.pem", f"{DIR}/key.pem")
    ctx.load_verify_locations(f"{DIR}/bundle.pem")
    return ctx


def peer(tls):
    cert = tls.getpeercert()
    uris = [v for k, v in cert.get("subjectAltName", ()) if k == "URI"]
    return (uris[0] if len(uris) == 1 else None), cert["serialNumber"]


mode, peer_id = sys.argv[1], sys.argv[2]
if mode == "serve":
    seen, ctx = stamp(), context(ssl.PROTOCOL_TLS_SERVER)
    server = socket.create_server(("", 8443))
    while True:
        conn, _ = server.accept()
        try:
            if (now := stamp()) != seen:
                # Between hanko's renames the new SVID may meet the old key: keep the previous
                # context and try again on the next handshake.
                ctx, seen = context(ssl.PROTOCOL_TLS_SERVER), now
                print("files-changed", flush=True)
        except (OSError, ssl.SSLError) as e:
            print("kept previous files:", e, flush=True)
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                got, _ = peer(tls)
                print("peer", got, flush=True)
                tls.sendall(b"hello\n" if got == peer_id else b"denied\n")
        except (OSError, ssl.SSLError) as e:
            print("refused:", e, flush=True)
else:
    with context(ssl.PROTOCOL_TLS_CLIENT).wrap_socket(
        socket.create_connection((sys.argv[3], 8443), timeout=10)
    ) as tls:
        got, serial = peer(tls)
        if got != peer_id:
            sys.exit(f"server is {got}, not {peer_id}")
        answer = tls.recv(64).decode().strip()
        print(serial, answer)
        sys.exit(0 if answer == "hello" else 1)
