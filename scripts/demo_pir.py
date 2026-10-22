#!/usr/bin/env python3
"""Two real local processes; non-collusion remains an assumption."""
import selectors
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["cargo", "build", "--locked", "-p", "oblivion-pir", "--bins"], cwd=ROOT, check=True)
    servers = []
    with tempfile.TemporaryDirectory(prefix="oblivion-pir-") as directory:
        try:
            addresses = []
            for number in [1, 2]:
                database = Path(directory) / f"registry-{number}.bin"
                database.write_bytes(b"".join(bytes([i])*128 for i in range(16)))
                server = subprocess.Popen([str(ROOT/"target/debug/pir-server"), "127.0.0.1:0", str(database), "128"], stdout=subprocess.PIPE, text=True)
                servers.append(server)
                with selectors.DefaultSelector() as selector:
                    selector.register(server.stdout, selectors.EVENT_READ)
                    if not selector.select(timeout=10):
                        raise TimeoutError("PIR server did not become ready")
                address = server.stdout.readline().strip()
                if not address:
                    raise RuntimeError("PIR server exited during startup")
                addresses.append(address)
            response = subprocess.check_output([str(ROOT/"target/debug/pir-client"), *addresses, "16", "128", "7"], text=True)
            assert bytes.fromhex(response) == bytes([7])*128
            print("Retrieved record 7 through two separate PIR server processes (128 bytes).")
            print("Local process separation simulates non-collusion; it does not enforce it.")
        finally:
            for server in servers:
                server.terminate()
            for server in servers:
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__": main()
