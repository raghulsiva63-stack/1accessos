"""Upload only the checksum-pinned files accepted by the temporary release function.

Deploy the prepared function configuration first. After publishing, redeploy the
checked-in closed configuration, verify HTTP 410 and remove the temporary token.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
args = parser.parse_args()
config = json.loads((args.directory / "release-config.json").read_text())
if config["expires_at"] <= time.time() * 1000:
    raise SystemExit("Publishing authorization expired. Prepare a new reviewed deployment.")
token = (args.directory / "release-token").read_text()
if hashlib.sha256(token.encode()).hexdigest() != config["token_sha256"]:
    raise SystemExit("Release token does not match the deployed configuration.")
endpoint = "https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/publish-desktop-release"
public = "https://wkkmyacbhqloubtwvjom.supabase.co/storage/v1/object/public/passkey-x-client-releases/"
for file in config["files"]:
    path = args.directory / file["filename"]
    if path.parent.resolve() != args.directory.resolve():
        raise SystemExit("Invalid release filename.")
    body = path.read_bytes()
    if len(body) != file["bytes"] or hashlib.sha256(body).hexdigest() != file["sha256"]:
        raise SystemExit("Local release bytes changed after review.")
    request = urllib.request.Request(endpoint + "?" + urllib.parse.urlencode({"file": file["filename"]}), data=body, method="POST", headers={"Content-Type": "application/octet-stream", "x-release-token": token})
    try:
        with urllib.request.urlopen(request, timeout=90) as result:
            if result.status != 201:
                raise SystemExit(f"Unexpected upload response: {result.status}")
    except urllib.error.HTTPError as error:
        # A retry can encounter an existing immutable object. Only identical
        # public bytes below allow that conflict to count as completed.
        if error.code != 409:
            raise SystemExit(f"Release upload rejected: HTTP {error.code}") from None
    with urllib.request.urlopen(public + file["objectPath"], timeout=90) as result:
        published = result.read()
    if len(published) != file["bytes"] or hashlib.sha256(published).hexdigest() != file["sha256"]:
        raise SystemExit("Public release verification failed.")
    print(f"Published and verified {file['filename']}")
