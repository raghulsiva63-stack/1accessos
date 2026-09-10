"""Stage one verified Android CI artifact as bounded static repository assets."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('artifacts', type=Path)
parser.add_argument('--commit', required=True)
parser.add_argument('--run', required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
release = json.loads((args.artifacts / 'release.json').read_text())
version = '0.1.0'
filename = f'passkey-x-android-{version}-preview.apk'
assert (release['version'], release['platform'], release['filename'], release['commit'], str(release['run'])) == (version, 'android', filename, args.commit, args.run), 'Unexpected Android provenance'
body = (args.artifacts / filename).read_bytes()
digest = hashlib.sha256(body).hexdigest()
assert body[:4] == b'PK\x03\x04' and digest == release['sha256'] and len(body) == release['bytes'], 'Android integrity check failed'
assert (args.artifacts / (filename + '.sha256')).read_text() == f'{digest}  {filename}\n', 'Sidecar mismatch'
output = root / 'releases/android' / version
if output.exists(): raise SystemExit('Do not replace an existing versioned release')
output.mkdir(parents=True)
parts = []
for index, start in enumerate(range(0, len(body), 524288)):
    name = f'part-{index:03d}.bin'
    (output / name).write_bytes(body[start:start + 524288]); parts.append(name)
(output / 'manifest.json').write_text(json.dumps({**release, 'url': f'/downloads/android/{version}/{filename}', 'parts': parts}, indent=2) + '\n')
print('Verified and staged Android preview.')
