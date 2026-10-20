#!/usr/bin/env python3
"""Build a pinned disposable shb transport without modifying either checkout."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

REVISION = '48b2d7e2ca138ea9f69190cd3ae4112058fb56d7'


def main(repo, output):
    output.mkdir(parents=True)
    source = output / 'source'
    source.mkdir()
    here = Path(__file__).resolve().parent
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', REVISION])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter='data')
    shutil.copy2(here / 'stop-batch-peer-main.rs', source / 'src/main.rs')
    conn = source / 'src/quic/conn.rs'
    conn.write_text(conn.read_text() + '\n' + (here / 'sparse-ack-peer-methods.rs').read_text())
    target = Path(os.environ.get('NATIVE_PEER_TARGET_DIR', output / 'target')).resolve()
    env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(target))
    commands = [['cargo', 'test', '--locked', '--bin', 'shb', 'peer_tests'],
                ['cargo', 'test', '--release', '--locked', '--bin', 'shb', 'peer_tests'],
                ['cargo', 'clippy', '--locked', '--bin', 'shb', '--', '-D', 'warnings'],
                ['cargo', 'build', '--release', '--locked', '--bin', 'shb']]
    for command in commands:
        subprocess.run(command, cwd=source, env=env, check=True)
    binary = output / 'stop-batch-peer'
    shutil.copy2(target / 'release/shb', binary)
    binary.chmod(0o555)
    (output / 'manifest.json').write_text(json.dumps(dict(
        revision=REVISION, commands=commands,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        rustc=subprocess.check_output(['rustc', '-Vv'], text=True),
        source_sha256={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted((source / 'src').rglob('*.rs'))},
    ), indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main(*(Path(p).resolve() for p in sys.argv[1:]))
