"""Verify downloaded CI artifacts and prepare a finite release publishing request.

Input directory: windows-x64/, macos-universal/, linux-x64/, each containing the
files from one checksum-verified GitHub Actions artifact. The release token and
temporary configuration are written only to an explicitly chosen scratch folder.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import time

parser = argparse.ArgumentParser()
parser.add_argument("artifacts", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--commit", required=True)
parser.add_argument("--run", required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
output = args.output.resolve()
if output == root or root in output.parents:
    raise SystemExit("Keep temporary publishing credentials outside the repository.")
if output.exists():
    raise SystemExit("Choose a new output directory; existing releases are not replaced.")
lock_hash = hashlib.sha256((root / "apps/desktop/src-tauri/Cargo.lock").read_bytes()).hexdigest()
version = json.loads((root / "apps/desktop/src-tauri/tauri.conf.json").read_text())["version"]
files, platforms = [], []
for platform, suffix in [("windows-x64", ".exe"), ("macos-universal", ".dmg"), ("linux-x64", ".deb")]:
    directory = args.artifacts / platform
    release = json.loads((directory / "release.json").read_text())
    filename = f"passkey-x-desktop-{version}-{platform}{suffix}"
    if (release["version"], release["platform"], release["filename"], release["commit"], str(release["run"])) != (version, platform, filename, args.commit, args.run):
        raise SystemExit(f"Unexpected build provenance for {platform}")
    if hashlib.sha256((directory / "Cargo.lock").read_bytes()).hexdigest() != lock_hash:
        raise SystemExit(f"Dependency lockfile differs for {platform}")
    body = (directory / filename).read_bytes()
    checksum = hashlib.sha256(body).hexdigest()
    if checksum != release["sha256"] or len(body) != release["bytes"]:
        raise SystemExit(f"Installer checksum/size mismatch for {platform}")
    if (directory / (filename + ".sha256")).read_text() != f"{checksum}  {filename}\n":
        raise SystemExit(f"Checksum sidecar mismatch for {platform}")
    platforms.append({**release, "url": f"/downloads/desktop/{version}/{filename}"})
    for name in [filename, filename + ".sha256"]:
        data = (directory / name).read_bytes()
        files.append({"filename": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "objectPath": f"desktop/{version}/{name}"})
output.mkdir(mode=0o700, parents=True)
for platform in platforms:
    for name in [platform["filename"], platform["filename"] + ".sha256"]:
        shutil.copyfile(args.artifacts / platform["platform"] / name, output / name)
token = secrets.token_hex(32)
token_path = output / "release-token"
with open(token_path, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as handle:
    handle.write(token)
config = {"token_sha256": hashlib.sha256(token.encode()).hexdigest(), "expires_at": int((time.time() + 1800) * 1000), "files": files}
(output / "release-config.json").write_text(json.dumps(config, indent=2) + "\n")
(output / "desktop-release.json").write_text(json.dumps({"version": version, "channel": "preview", "commit": args.commit, "run": args.run, "platforms": platforms}, indent=2) + "\n")
print(f"Verified {len(platforms)} platforms. Prepared six immutable files in {output}.")
