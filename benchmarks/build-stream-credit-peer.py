#!/usr/bin/env python3
"""Build the full-upload fixture from immutable shb objects, never checkout files."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

REVISION = 'eabad04e72a0d684da06e096077cc47aca595bbc'
repo, output = map(Path, sys.argv[1:])
output = output.resolve()
output.mkdir(parents=True, exist_ok=False)
source = output / 'source'
source.mkdir()
here = Path(__file__).resolve().parent
archive = subprocess.check_output(['git', '-C', str(repo), 'archive', REVISION])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(source, filter='data')
for src, dest in [('stream-credit-peer-main.rs', 'main.rs'), ('stream-credit-ledger.rs', 'credit_ledger.rs')]:
    shutil.copy2(here / src, source / 'src' / dest)
conn = source / 'src/quic/conn.rs'
conn.write_text(conn.read_text() + '\n' + (here / 'sparse-ack-peer-methods.rs').read_text() + '''
impl Connection {
    pub fn credit_probe_limits(&self) -> (u64, u64, u64) {
        (self.params.initial_max_stream_data_bidi_remote,
         self.params.initial_max_streams_uni, self.params.initial_max_stream_data_uni)
    }
}
''')
target = Path(os.environ.get('NATIVE_PEER_TARGET_DIR', output / 'target')).resolve()
env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(target))
commands = [['cargo', 'test', '--locked', '--bin', 'shb'],
            ['cargo', 'test', '--release', '--locked', '--bin', 'shb'],
            ['cargo', 'clippy', '--locked', '--bin', 'shb', '--', '-D', 'warnings'],
            ['cargo', 'build', '--release', '--locked', '--bin', 'shb']]
for command in commands:
    subprocess.run(command, cwd=source, env=env, check=True)
binary = output / 'stream-credit-peer'
shutil.copy2(target / 'release/shb', binary)
binary.chmod(0o555)
(output / 'manifest.json').write_text(json.dumps(dict(
    revision=REVISION, commands=commands, sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    compiler=subprocess.check_output(['rustc', '-Vv'], text=True),
    source_sha256={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted((source / 'src').rglob('*.rs'))},
), indent=2) + '\n')
print(binary)
