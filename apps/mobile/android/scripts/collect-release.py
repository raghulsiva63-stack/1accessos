import hashlib
import json
import os
import pathlib
import shutil

version = '0.1.0'
source = pathlib.Path('app/build/outputs/apk/preview/app-preview.apk')
destination = pathlib.Path('artifacts')
destination.mkdir(exist_ok=True)
filename = f'passkey-x-android-{version}-preview.apk'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
shutil.copyfile(source, destination / filename)
(destination / (filename + '.sha256')).write_text(f'{digest}  {filename}\n')
(destination / 'release.json').write_text(json.dumps({'version': version, 'platform': 'android', 'filename': filename, 'bytes': len(data), 'sha256': digest, 'commit': os.environ['RELEASE_COMMIT'], 'run': os.environ['RELEASE_RUN'], 'minAndroid': 9, 'signing': 'Temporary preview key; not a Play Store release'}, indent=2) + '\n')
