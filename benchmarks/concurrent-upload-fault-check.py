#!/usr/bin/env python3
"""Exercise controller cleanup with a real sibling and a faulty producer."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from concurrent_uploads import coordinate
from udp_accounting import require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server', type=lambda s: Path(s).resolve())
    parser.add_argument('peer', type=lambda s: Path(s).resolve())
    parser.add_argument('output', type=lambda s: Path(s).resolve())
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    available = sorted(os.sched_getaffinity(0))
    clients = [c for c in available if c != 0] or available
    cpus = [clients[i % len(clients)] for i in range(2)]
    results = []
    # The proxy has its own process group only through the controller; it execs
    # the real binary for the healthy sibling and never creates grandchildren.
    for index in range(2):
        for fault in ('exit', 'stall', 'malformed', 'oversize'):
            case = args.output / f'{fault}-{index}'
            case.mkdir()
            wrapper = case / 'peer'
            code = ('#!/usr/bin/env python3\nimport os,sys,time\n'
                    'from pathlib import Path\n'
                    f'Path({str(case)!r}, "pid-"+os.environ["UPLOAD_PRODUCER_INDEX"]).write_text(str(os.getpid()))\n'
                    f'if int(os.environ["UPLOAD_PRODUCER_INDEX"]) == {index}:\n')
            action = dict(exit='sys.exit(7)', stall='time.sleep(30)',
                          malformed='print("{malformed}",flush=True); sys.stdin.read()',
                          oversize='print("x"*20000,flush=True); sys.stdin.read()')[fault]
            code += '    ' + action + '\n'
            code += f'os.execv({str(args.peer)!r}, [{str(args.peer)!r}, *sys.argv[1:]])\n'
            wrapper.write_text(code)
            wrapper.chmod(0o755)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            with (case / 'server.log').open('x') as log:
                server = subprocess.Popen([str(args.server), '--threads', '1', '--tcp', '0', '--quic', str(port)],
                                          stdout=log, stderr=log)
                try:
                    time.sleep(.2)
                    started = time.monotonic()
                    try:
                        coordinate(wrapper, server.pid, port, case, cpus, size=65543, timeout=1)
                    except (ValueError, BrokenPipeError) as error:
                        failure = str(error)
                    else:
                        raise AssertionError('faulty producer accepted')
                    require(time.monotonic() - started < 8, 'unbounded failure cleanup')
                    require((case / 'failure.txt').exists() and (case / 'udp.json').exists(), 'lost failure evidence')
                    pids = [int(p.read_text()) for p in case.glob('pid-*')]
                    require(pids and all(not Path(f'/proc/{p}').exists() for p in pids), 'orphan producer')
                    require(all((case / f'peer-{i}.jsonl').exists() and
                                (case / f'peer-{i}.stderr').exists() for i in range(2)), 'missing sibling output')
                    results.append(dict(index=index, fault=fault, rejected=True, error=failure, pids=pids))
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)
            (args.output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(dict(expected_failures=len(results), all_rejected=True)))


if __name__ == '__main__':
    main()
