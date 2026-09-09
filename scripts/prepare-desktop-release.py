"""Verify CI artifacts and stage checksum-pinned static desktop release assets.

Verify each downloaded GitHub artifact ZIP against GitHub's archive digest first.
Extract into windows-x64/, macos-universal/, linux-x64/ below the input directory.
No publishing credentials or backend services are needed.
"""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("artifacts", type=Path)
parser.add_argument("--commit", required=True)
parser.add_argument("--run", required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
# Git's Windows checkout can use CRLF. Compare normalized text, preserving every
# dependency, checksum and version in the locked build input.
lock_hash = hashlib.sha256((root / "apps/desktop/src-tauri/Cargo.lock").read_text().encode()).hexdigest()
version = json.loads((root / "apps/desktop/src-tauri/tauri.conf.json").read_text())["version"]
output = root / "releases/desktop" / version
if output.exists():
    raise SystemExit("A versioned release already exists. Do not replace published installers.")
platforms = []
for platform, suffix in [("windows-x64", ".exe"), ("macos-universal", ".dmg"), ("linux-x64", ".deb")]:
    directory = args.artifacts / platform
    release = json.loads((directory / "release.json").read_text())
    filename = f"passkey-x-desktop-{version}-{platform}{suffix}"
    if (release["version"], release["platform"], release["filename"], release["commit"], str(release["run"])) != (version, platform, filename, args.commit, args.run):
        raise SystemExit(f"Unexpected build provenance for {platform}")
    if hashlib.sha256((directory / "Cargo.lock").read_text().encode()).hexdigest() != lock_hash:
        raise SystemExit(f"Dependency lockfile differs for {platform}")
    body = (directory / filename).read_bytes()
    checksum = hashlib.sha256(body).hexdigest()
    if checksum != release["sha256"] or len(body) != release["bytes"]:
        raise SystemExit(f"Installer checksum/size mismatch for {platform}")
    if (directory / (filename + ".sha256")).read_text() != f"{checksum}  {filename}\n":
        raise SystemExit(f"Checksum sidecar mismatch for {platform}")
    platforms.append(({**release, "url": f"/downloads/desktop/{version}/{filename}"}, body))
output.mkdir(parents=True)
manifest = {"version": version, "channel": "preview", "commit": args.commit, "run": args.run, "platforms": []}
for release, body in platforms:
    directory = output / release["platform"]
    directory.mkdir()
    parts = []
    # Bounded blobs allow repository connectors to transport installers without
    # oversized requests. Builds reconstruct and verify the complete installer.
    for index, start in enumerate(range(0, len(body), 524288)):
        name = f"part-{index:03d}.bin"
        (directory / name).write_bytes(body[start:start + 524288])
        parts.append(f"{release['platform']}/{name}")
    manifest["platforms"].append({**release, "parts": parts})
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Verified and staged {len(platforms)} desktop installers at {output}.")
