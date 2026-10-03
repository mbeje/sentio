"""
TCP Port Scanner — concurrent, timeout-safe, banner-grabbing capable.
Reuses the probe connection for banner capture to avoid double-connect issues.
"""
import socket
import concurrent.futures
from typing import List, Tuple
from config import Config
from utils.logger import get_logger

logger = get_logger("scanner")


class PortScanner:
    """
    Fast multi-threaded TCP connect scanner.
    """

    def __init__(self):
        self.timeout = Config.SCAN_TIMEOUT_SECONDS
        self.max_workers = Config.SCAN_WORKERS
        self.default_ports = Config.DEFAULT_PORTS

    def _probe_port(self, target: str, port: int) -> Tuple[int, bool, str]:
        """
        Attempt TCP connection and grab banner in a single flow.
        Returns (port, is_open, banner).
        """
        banner = ""
        sock = None
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            # Set a slightly longer timeout for banner reading
            sock.settimeout(2.0)

            # For HTTP/HTTPS, send a trigger to get a response
            if port in (80, 8080, 443, 8443):
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
                except Exception:
                    pass

            # For SSH and other text protocols, the server usually sends banner immediately
            # For some protocols, we may need to wait a moment
            try:
                banner_bytes = sock.recv(1024)
                banner = banner_bytes.decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                # No banner received — still counts as open
                banner = ""
            except Exception:
                banner = ""

            return port, True, banner

        except (socket.timeout, ConnectionRefusedError, OSError):
            return port, False, ""
        except Exception as e:
            logger.debug(f"Probe error {target}:{port} — {e}")
            return port, False, ""
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def scan(self, target: str, ports: List[int] = None) -> List[dict]:
        """
        Scan target ports concurrently. Return list of open port dicts.
        """
        ports = ports or self.default_ports
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._probe_port, target, p): p for p in ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "banner": banner,
                    })

        open_ports.sort(key=lambda x: x["port"])
        logger.info(f"Scan complete: {len(open_ports)} open ports on {target}")
        return open_ports
