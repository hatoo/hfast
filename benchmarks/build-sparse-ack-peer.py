#!/usr/bin/env python3
"""Build a native controlled ACK or two-connection burst peer from pinned shb Git objects.

Usage: build-sparse-ack-peer.py /path/to/shb /new/output/directory [--burst]
Neither working checkout is read or modified. All workload modifications live in
an extracted archive; the production servers remain immutable and uninstrumented.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

revision = '48b2d7e2ca138ea9f69190cd3ae4112058fb56d7'
burst = len(sys.argv) == 4 and sys.argv[3] == '--burst'
assert len(sys.argv) == 3 or burst
repo, output = map(Path, sys.argv[1:3])
output = output.resolve()
output.mkdir(parents=True)
source = output / 'source'
source.mkdir()
here = Path(__file__).parent
archive = subprocess.check_output(['git', '-C', str(repo), 'archive', revision])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(source, filter='data')
main = 'burst-peer-main.rs' if burst else 'sparse-ack-peer-main.rs'
(source / 'src/main.rs').write_text((here / main).read_text())
conn = source / 'src/quic/conn.rs'
conn.write_text(conn.read_text() + '\n' + (here / 'sparse-ack-peer-methods.rs').read_text())
target = Path(os.environ.get('NATIVE_PEER_TARGET_DIR', output / 'target')).resolve()
env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(target))
command = ['cargo', 'build', '--release', '--locked', '--bin', 'shb']
subprocess.run(command, cwd=source, env=env, check=True)
subprocess.run(['cargo', 'test', '--release', '--locked', '--bin', 'shb', 'peer_tests'],
               cwd=source, env=env, check=True)
binary = output / ('burst-peer' if burst else 'sparse-ack-peer')
shutil.copy2(target / 'release/shb', binary)
binary.chmod(0o555)
(output / 'manifest.json').write_text(json.dumps(dict(
    shb=revision, command=command, workload=main,
    sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    compiler=subprocess.check_output(['rustc', '-Vv'], text=True),
    source_sha256={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted((source / 'src').rglob('*.rs'))},
), indent=2) + '\n')
print(binary)
