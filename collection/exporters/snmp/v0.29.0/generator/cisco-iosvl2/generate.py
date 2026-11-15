"""Generate the IOSvL2 module with upstream snmp_exporter v0.29.0 tooling."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", required=True, type=Path)
    parser.add_argument("--base-mibs", type=Path, default=Path("/usr/share/snmp/mibs"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    lock = json.loads((directory/"mibs.lock.json").read_text())
    with tempfile.TemporaryDirectory(prefix="omnisor-iosvl2-mibs-") as temporary:
        mibs = Path(temporary)
        for entry in lock["files"]:
            with urllib.request.urlopen(entry["url"], timeout=30) as response:
                body = response.read()
            if hashlib.sha256(body).hexdigest() != entry["sha256"]:
                raise RuntimeError("MIB source checksum mismatch: "+entry["name"])
            (mibs/entry["name"]).write_bytes(body)
        subprocess.run([str(args.generator.resolve()), "generate", "-m", str(args.base_mibs), "-m", str(mibs),
                        "-g", str(directory/"generator.yml"), "-o", str(args.output or directory.parent.parent/"cisco_ios_legacy.yaml")], check=True)


if __name__ == "__main__":
    main()
