#!/usr/bin/env python3
"""Build a private, bounded native cancellation sustained peer with bounded histories and exact receipts."""
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


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'shared fixture marker changed: {old!r}')
    return text.replace(old, new, 1)


def main(repo, output):
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    source.mkdir()
    here = Path(__file__).resolve().parent
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', REVISION])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter='data')
    peer = (here / 'stop-batch-peer-main.rs').read_text()
    peer = replace(peer, 'fn main() -> Result<()> {', 'fn stop_main() -> Result<()> {')
    peer = replace(peer, '    packet_count: usize,', '''    packet_count: usize,
    handshake_sent: u64,
    handshake_received: u64,
    gso_segment_excess: u64,
    flow_packets: Vec<(u64, u64)>,
    retired_sent_packets: u64,
    max_packet_history: usize,
    cancellation_started: Option<Instant>,
    cancellation_samples: Vec<(u64,u64)>,''')
    peer = replace(peer, '        let mut wire = Vec::with_capacity(1200);', '''        let mut wire = Vec::with_capacity(1200);
        let mut handshake_sent = 0;
        let mut handshake_received = 0;''')
    peer = replace(peer, '                ensure!(socket.send(&wire)? == wire.len());', '''                ensure!(socket.send(&wire)? == wire.len());
                handshake_sent += 1;''')
    peer = replace(peer, '            let n = socket.recv(&mut buf)?;', '''            let n = socket.recv(&mut buf)?;
            handshake_received += 1;''')
    peer = replace(peer, '            packet_count: 0,', '''            packet_count: 0,
            handshake_sent,
            handshake_received,
            gso_segment_excess: 0,
            flow_packets: Vec::with_capacity(129),
            retired_sent_packets: 0,
            max_packet_history: 0,
            cancellation_started: None,
            cancellation_samples: Vec::new(),''')
    peer = replace(peer, '                    self.reset_count += 1;', '''                    self.reset_count += 1;
                    let start = self.cancellation_started.context("reset before cancellation interval")?;
                    self.cancellation_samples.push((id,start.elapsed().as_nanos() as u64));''')
    peer = replace(peer, '                Frame::MaxStreams { uni: false, limit } => {', '''                Frame::MaxStreamData { id, limit } => {
                    ensure!(limit == 3 * HALF && self.resets.as_ref().is_some_and(|batch| batch.expected.contains(&id)), "wrong stream credit");
                    ack_only = false;
                }
                Frame::MaxStreams { uni: false, limit } => {''')
    peer = replace(peer, '                    self.max_data = self.max_data.max(limit);', """                    let acknowledged = self.acked_through.context("credit without ACK")?;
                    let flow = self.flow_packets.iter().find(|(pn,_)| *pn == acknowledged)
                        .context("credit without flow snapshot")?.1;
                    ensure!(limit >= self.max_data &&
                        (limit == self.max_data || limit == (1 << 30) + flow),
                        "wrong cumulative connection credit: {limit}, old {}, flow {flow}, ACK {acknowledged}", self.max_data);
                    self.max_data = limit;""")
    peer = replace(peer, '        self.sent_packets.push(pn);', """        self.sent_packets.push(pn);
        self.flow_packets.push((pn,self.sent_data));""")
    peer = replace(peer, '        let pn = self.conn.probe_seal(payload, &mut self.wire)?;', """        ensure!(payload.len() <= SEGMENT - 29, "oversized native payload");
        let pn = self.conn.probe_seal(payload, &mut self.wire)?;
        ensure!(self.wire.len() <= SEGMENT, "oversized native packet");""")
    (source / 'src/main.rs').write_text(peer + '\n' + (here / 'receive-credit-cancel.rs').read_text().replace('//!', '//'))
    shutil.copy2(here / 'stream-credit-control.rs', source / 'src/credit_control.rs')
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
    env = os.environ | {'CARGO_TARGET_DIR': str(target), 'CARGO_INCREMENTAL': '0'}
    commands = [['rustfmt', '--edition', '2024', '--config', 'skip_children=true', 'src/main.rs'],
                ['cargo', 'test', '--locked', '--bin', 'shb'],
                ['cargo', 'test', '--release', '--locked', '--bin', 'shb'],
                ['cargo', 'clippy', '--locked', '--bin', 'shb', '--', '-D', 'warnings'],
                ['cargo', 'build', '--release', '--locked', '--bin', 'shb']]
    for command in commands:
        subprocess.run(command, cwd=source, env=env, check=True)
    binary = output / 'receive-credit-cancel-peer'
    shutil.copy2(target / 'release/shb', binary)
    binary.chmod(0o555)
    (output / 'manifest.json').write_text(json.dumps(dict(
        revision=REVISION, commands=commands, sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        compiler=subprocess.check_output(['rustc', '-Vv'], text=True),
        source_sha256={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted((source / 'src').rglob('*.rs'))},
        inputs={name:hashlib.sha256((here/name).read_bytes()).hexdigest() for name in
                ['stop-batch-peer-main.rs','sparse-ack-peer-methods.rs','stream-credit-control.rs',
                 'receive-credit-cancel.rs','build-receive-credit-cancel.py']},
        timing="native fixed-work interval; trace must be disabled",
    ), indent=2)+'\n')


if __name__ == '__main__':
    main(*(Path(p).resolve() for p in sys.argv[1:]))
