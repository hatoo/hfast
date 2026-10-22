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

REVISION = '12e95af17ef6015020776ab65996bef9531099e0'


def main(repo, output, *, persistent=False):
    output.mkdir(parents=True)
    source = output / 'source'
    source.mkdir()
    here = Path(__file__).resolve().parent
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', REVISION])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter='data')
    main_source = 'persistent-peer-main.rs' if persistent else 'crypto-churn-peer-main.rs'
    for name, target in [(main_source, 'main.rs'),
                         ('crypto-churn-schedule.rs', 'crypto_schedule.rs')]:
        shutil.copy2(here / name, source / 'src' / target)
    conn = source / 'src/quic/conn.rs'
    text = conn.read_text()
    replacements = [
        ('pub struct Connection {', 'pub struct Connection {\n    churn: Option<crate::crypto_schedule::Audit>,'),
        ('        Ok(Self {\n            tls,', '        Ok(Self {\n            churn: None,\n            tls,'),
        ('        // Handshake bytes that have not been sent yet,',
         '        let controlled = self.churn.is_some() && space != Space::Data;\n'
         '        if controlled {\n'
         '            ack_eliciting |= self.churn_crypto(space, out, room(out), frames)?;\n'
         '        }\n\n        // Handshake bytes that have not been sent yet,'),
    ]
    for old, new in replacements:
        if text.count(old) != 1:
            raise RuntimeError(f'pinned source mismatch: {old}')
        text = text.replace(old, new)
    loop_start = '        loop {\n            let s = &self.spaces[space as usize];\n            let avail = room(out);'
    if text.count(loop_start) != 1:
        raise RuntimeError('pinned CRYPTO loop mismatch')
    start = text.index(loop_start)
    stop = text.index('\n\n        if space == Space::Data', start)
    original_loop = '\n'.join('    ' + line for line in text[start:stop].splitlines())
    text = text[:start] + '        if !controlled {\n' + original_loop + '\n        }' + text[stop:]
    text += '\n' + (here / 'sparse-ack-peer-methods.rs').read_text()
    text += '\n' + (here / 'crypto-churn-methods.rs').read_text()
    conn.write_text(text)
    target = Path(os.environ.get('NATIVE_PEER_TARGET_DIR', output / 'target')).resolve()
    env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(target))
    commands = [['cargo', 'test', '--locked', '--bin', 'shb', 'peer_tests'],
                ['cargo', 'test', '--release', '--locked', '--bin', 'shb', 'peer_tests'],
                ['cargo', 'clippy', '--locked', '--bin', 'shb', '--', '-D', 'warnings'],
                ['cargo', 'build', '--release', '--locked', '--bin', 'shb']]
    for command in commands:
        subprocess.run(command, cwd=source, env=env, check=True)
    binary = output / ('persistent-peer' if persistent else 'crypto-churn-peer')
    shutil.copy2(target / 'release/shb', binary)
    binary.chmod(0o555)
    (output / 'manifest.json').write_text(json.dumps(dict(
        revision=REVISION, commands=commands, workload=main_source,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        rustc=subprocess.check_output(['rustc', '-Vv'], text=True),
        source_sha256={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted((source / 'src').rglob('*.rs'))},
    ), indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    persistent = len(sys.argv) == 4 and sys.argv[3] == '--persistent'
    if len(sys.argv) != 3 and not persistent:
        raise SystemExit('usage: builder SHB OUTPUT [--persistent]')
    main(*(Path(p).resolve() for p in sys.argv[1:3]), persistent=persistent)
