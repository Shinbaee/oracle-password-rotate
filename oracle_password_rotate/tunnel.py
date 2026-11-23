"""SSH local port forwarding for databases whose listener only accepts connections from the host itself.

    this machine 127.0.0.1:<free port>  --SSH-->  db server  -->  127.0.0.1:1521 (as seen there)

Only port 22 needs to be open. Unknown host keys are refused, not added.

SSH forwards a plain byte stream. TCP urgent data ("out of band") does not survive it, which matters
for Oracle Net: see --disable-oob in the README.
"""

from __future__ import annotations

import select
import socket
import threading


class TunnelError(Exception):
    pass


class Tunnel:
    def __init__(self, ssh_host: str, ssh_user: str, remote_host: str, remote_port: int, *,
                 ssh_port: int = 22, password: str | None = None, key_file: str | None = None,
                 known_hosts: str | None = None, timeout: float = 15.0):
        self.args = dict(ssh_host=ssh_host, ssh_user=ssh_user, ssh_port=ssh_port, password=password,
                         key_file=key_file, known_hosts=known_hosts, timeout=timeout)
        self.remote = (remote_host, remote_port)
        self.local_port = 0
        self._client = None
        self._server = None
        self._closing = threading.Event()

    def __enter__(self) -> "Tunnel":
        import paramiko
        a = self.args
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if a["known_hosts"]:
            client.load_host_keys(a["known_hosts"])
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(a["ssh_host"], port=a["ssh_port"], username=a["ssh_user"], password=a["password"],
                           key_filename=a["key_file"], timeout=a["timeout"], banner_timeout=a["timeout"],
                           auth_timeout=a["timeout"], allow_agent=False,
                           look_for_keys=a["key_file"] is None and a["password"] is None)
        except Exception as e:  # paramiko raises many types; the message is enough here
            raise TunnelError(f"SSH to {a['ssh_host']}:{a['ssh_port']} failed: {type(e).__name__}: {e}") from None
        self._client = client
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))  # loopback only: nobody else on this machine's network can use it
        server.listen(4)
        self._server = server
        self.local_port = server.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def _accept(self) -> None:
        while not self._closing.is_set():
            try:
                sock, peer = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._pipe, args=(sock, peer), daemon=True).start()

    def _pipe(self, sock: socket.socket, peer) -> None:
        try:
            chan = self._client.get_transport().open_channel("direct-tcpip", self.remote, peer)
        except Exception:
            sock.close()
            return
        try:
            while not self._closing.is_set():
                ready, _, _ = select.select([sock, chan], [], [], 0.5)
                if sock in ready:
                    data = sock.recv(32768)
                    if not data:
                        break
                    chan.sendall(data)
                if chan in ready:
                    data = chan.recv(32768)
                    if not data:
                        break
                    sock.sendall(data)
        except OSError:
            pass
        finally:
            chan.close()
            sock.close()

    def __exit__(self, *exc) -> None:
        self._closing.set()
        if self._server:
            self._server.close()
        if self._client:
            self._client.close()
