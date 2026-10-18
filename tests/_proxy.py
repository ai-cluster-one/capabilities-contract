"""A TCP forwarder in front of the test server that can refuse a connect, cut every
connection it carries, or stop forwarding, as a flapping network does. It forwards
bytes unread, so TLS passes through it."""

from __future__ import annotations

import contextlib
import select
import socket
import threading


class Proxy:
    def __init__(self, host: str, port: int):
        self.target = (host, port)
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.port = self.listener.getsockname()[1]
        self.accepted = 0
        self.refuse = 0
        self.stalled = threading.Event()
        self._pairs: list[tuple[socket.socket, socket.socket]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _addr = self.listener.accept()
            except OSError:
                return
            with self._lock:
                self.accepted += 1
                refuse = self.refuse > 0
                if refuse:
                    self.refuse -= 1
            if refuse:
                client.close()
                continue
            try:
                upstream = socket.create_connection(self.target, timeout=5)
            except OSError:
                client.close()
                continue
            with self._lock:
                self._pairs.append((client, upstream))
            threading.Thread(target=self._pump, args=(client, upstream), daemon=True).start()

    def _pump(self, a: socket.socket, b: socket.socket) -> None:
        peers = {a: b, b: a}
        try:
            while not self._stop.is_set():
                ready, _w, _x = select.select([a, b], [], [], 0.05)
                if self.stalled.is_set():
                    continue
                for sock in ready:
                    data = sock.recv(65536)
                    if not data:
                        return
                    peers[sock].sendall(data)
        except OSError:
            return
        finally:
            for sock in (a, b):
                with contextlib.suppress(OSError):
                    sock.close()

    def cut(self) -> None:
        """End every connection carried now, as a reset network does."""
        with self._lock:
            pairs, self._pairs = self._pairs, []
        for a, b in pairs:
            for sock in (a, b):
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)

    def close(self) -> None:
        self._stop.set()
        self.cut()
        with contextlib.suppress(OSError):
            self.listener.close()
