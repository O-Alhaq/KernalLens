"""Controlled TCP/UDP echo traffic for the isolated M4 integration test."""

import argparse
from pathlib import Path
import socket


def server(ready):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM
    ) as udp:
        tcp.settimeout(8)
        udp.settimeout(8)
        tcp.bind(("192.0.2.2", 32080))
        udp.bind(("192.0.2.2", 32081))
        tcp.listen(1)
        Path(ready).touch()
        connection, _ = tcp.accept()
        with connection:
            connection.settimeout(8)
            data = b""
            while len(data) < len(b"kernellens-tcp"):
                chunk = connection.recv(1024)
                assert chunk, "unexpected TCP EOF"
                data += chunk
            assert data == b"kernellens-tcp"
            connection.sendall(data)
        data, peer = udp.recvfrom(1024)
        assert data == b"kernellens-udp"
        udp.sendto(data, peer)


def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        tcp.settimeout(5)
        tcp.bind(("192.0.2.1", 45000))
        tcp.connect(("192.0.2.2", 32080))
        tcp.sendall(b"kernellens-tcp")
        response = b""
        while len(response) < len(b"kernellens-tcp"):
            chunk = tcp.recv(1024)
            assert chunk, "unexpected TCP EOF"
            response += chunk
        assert response == b"kernellens-tcp"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(5)
        udp.bind(("192.0.2.1", 45001))
        udp.sendto(b"kernellens-udp", ("192.0.2.2", 32081))
        data, peer = udp.recvfrom(1024)
        assert data == b"kernellens-udp" and peer == ("192.0.2.2", 32081)
    print("PASS: ordinary TCP and UDP echo traffic delivered through XDP_PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--ready")
    arguments = parser.parse_args()
    if arguments.mode == "server":
        if not arguments.ready:
            parser.error("server requires --ready")
        server(arguments.ready)
    else:
        client()
