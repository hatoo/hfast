#!/usr/bin/env python3
"""Bounded paired CRYPTO campaign; each trial owns a fresh network namespace.

Run as root on a dedicated runner after all builds and correctness checks.
This reports evidence and promising cells, never automatic acceptance.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys

import crypto_churn as c


def save(path, value):
    with path.open('x') as out:
        json.dump(value, out, indent=2)
        out.write('\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def topology():
    rows = []
    for cpu in sorted(os.sched_getaffinity(0)):
        root = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
        rows.append(dict(cpu=cpu, core=int((root / 'core_id').read_text()),
                         socket=int((root / 'physical_package_id').read_text()),
                         siblings=(root / 'thread_siblings_list').read_text().strip()))
    return rows


def client_cpus(rows, producers):
    c.require(producers in (1, 4), 'invalid producer count')
    server = next((r for r in rows if r['cpu'] == 0), None)
    c.require(server is not None, 'server CPU 0 unavailable')
    seen = {(server['socket'], server['core'])}
    available = []
    for row in rows:
        physical = (row['socket'], row['core'])
        if physical not in seen:
            available.append(row['cpu'])
            seen.add(physical)
    c.require(available, 'no physical client core disjoint from server')
    # Four processes can share fewer than four *client* cores on small hosts.
    # This is explicit in every report, and never uses the server's SMT sibling.
    return [available[i % len(available)] for i in range(producers)]


def orders(candidate_first=False):
    first = ['candidate', 'baseline'] if candidate_first else ['baseline', 'candidate']
    return [first, first[::-1], first]


def audit(row, config):
    c.require(not row['shared_namespace'] and not row['smoke'], 'non-timing result')
    c.require(row['network_namespace'] != config['parent_namespace'], 'namespace was not isolated')
    for key in ('mode', 'empty_prefix', 'client_cpus', 'warmup'):
        c.require(row[key] == config[key], f'workload changed: {key}')
    count, producers = config['count'], len(config['client_cpus'])
    c.require(row['gro'] and row['per_producer'] == count and row['producers'] == producers,
              'workload population changed')
    c.require(row['inputs'] == config['inputs'], 'binary identity changed')
    c.require(row['errors'] == 0 and row['completed'] == count * producers, 'incomplete trial')
    c.require(len(row['workers']) == len(row['final']) == len(row['ready']) == producers,
              'missing producer')
    for worker in row['workers']:
        c.validate_done(worker, config['mode'], count, config['empty_prefix'])
    for ready, final in zip(row['ready'], row['final']):
        c.require(ready['warmup'] == config['warmup'], 'wrong warmup')
        c.require({k: v for k, v in final.items() if k != 'ledger'} == dict(
            phase='validated', retirement_probes=1, replacements_verified=config['warmup'] + count,
            maximum_server_addresses=1, port=ready['port'], failed=0), 'wrong final drain')
    for key in c.ERROR_COUNTERS:
        c.require(row['udp_before'][key] == row['udp_after'][key], f'UDP error {key}')
    delivered = sum(r['ledger']['sent_datagrams'] + r['ledger']['received_datagrams']
                    for r in row['final'])
    c.require(row['udp_after']['InDatagrams'] - row['udp_before']['InDatagrams'] == delivered,
              'final UDP ledger mismatch')
    for phase in ('before', 'after'):
        observations = row['socket_audit'][phase]
        c.require(len(observations) == producers + 1, 'missing socket audit')
        for obs in observations:
            c.require(obs['status'] == 'available' and obs['delta']['drops'] == 0,
                      'socket loss or unavailable audit')
            for sock in obs['snapshot']['sockets']:
                c.require(sock['drops'] == sock['diag_drops'] == 0, 'socket drops')
                if phase == 'after':
                    c.require(sock['rx_queue'] == sock['tx_queue'] == 0, 'undrained socket')
    for phase in ('affinity_before', 'affinity_after'):
        affinity = row[phase]
        c.require(affinity['server'] and all(v == [0] for v in affinity['server'].values()),
                  'server affinity changed')
        c.require(len(affinity['peers']) == producers, 'missing peer affinity')
        for core, peer in zip(config['client_cpus'], affinity['peers']):
            c.require(peer and all(v == [core] for v in peer.values()), 'peer affinity changed')


def metrics(row):
    samples = sorted(n for worker in row['workers'] for n in worker['latencies_ns'])
    seconds, total = row['seconds'], row['completed']
    c.require(math.isfinite(seconds) and seconds > 0, 'invalid wall time')
    server = sum(row['server_cpu'][k] for k in ('user', 'system'))
    peers = sum(p[k] for p in row['peer_cpu'] for k in ('user', 'system'))
    return dict(cps=total / seconds, seconds=seconds, completed=total, samples=len(samples),
                server_cpu_seconds=server, peer_cpu_seconds=peers,
                server_cpu_ns=server * 1e9 / total, peer_cpu_ns=peers * 1e9 / total,
                server_cores=row['server_cpu']['cores'],
                peer_cores=[p['cores'] for p in row['peer_cpu']],
                p50_ns=samples[math.ceil(.5 * len(samples)) - 1],
                p99_ns=samples[math.ceil(.99 * len(samples)) - 1])


def comparison(pair):
    result = {}
    for key in ('cps', 'server_cpu_ns', 'peer_cpu_ns', 'p50_ns', 'p99_ns'):
        base, candidate = (pair[v][key] for v in ('baseline', 'candidate'))
        result[key + '_change_pct'] = 100 * (candidate / base - 1) if base else None
    return result


def trial(config):
    c.require(os.readlink('/proc/self/ns/net') != config['parent_namespace'],
              'trial requires fresh namespace')
    c.require(config['inputs'] == {p: digest(p) for p in config['inputs']}, 'input changed')
    row = c.run(Path(config['server']), Path(config['peer']), Path(config['output']),
                config['client_cpus'], mode=config['mode'], count=config['count'],
                warmup=config['warmup'], timeout=config['timeout'],
                empty_prefix=config['empty_prefix'],
                share_client_cpus=len(set(config['client_cpus'])) < len(config['client_cpus']))
    audit(row, config)


def launch(config, config_path):
    save(config_path, config)
    command = ['unshare', '--net', 'sh', '-c', 'ip link set lo up && exec "$@"',
               'crypto-trial', sys.executable, str(Path(__file__).resolve()),
               '--trial', str(config_path)]
    save(config_path.with_suffix('.command.json'), command)
    with config_path.with_suffix('.stdout').open('x') as out, \
            config_path.with_suffix('.stderr').open('x') as err:
        subprocess.run(command, stdout=out, stderr=err, check=True)
    row = json.loads((Path(config['output']) / 'result.json').read_text())
    audit(row, config)
    return metrics(row)


def campaign(args):
    c.require(os.geteuid() == 0, 'campaign requires owned namespace privileges')
    c.require(32 <= args.empty_connections <= 10000 and 256 <= args.ordinary_connections <= 100000,
              'invalid fixed work bound')
    c.require(1 <= args.warmup <= 256 and 1 <= args.timeout <= 600, 'invalid bound')
    c.require(not any(k in os.environ for k in ('LD_PRELOAD', 'HFAST_GRO_PRELOAD')),
              'instrumented campaign')
    args.output.mkdir(parents=True)
    inputs = {str(p): digest(p) for p in (args.baseline, args.candidate, args.peer)}
    rows = topology()
    save(args.output / 'environment.json', dict(topology=rows, kernel=platform.uname()._asdict(),
         inputs=inputs, cpu_clock_ticks=os.sysconf('SC_CLK_TCK'),
         namespace=os.readlink('/proc/self/ns/net'), argv=sys.argv, backend='isolated loopback UDP'))
    summary = dict(primary=[], confirmation=[], decision='AWAITING_PERFORMANCE_VALIDATION')
    cells = [(p, mode, n) for p in (1, 4) for mode in ('normal', 'reverse') for n in (0, 512)]
    for phase in ('primary', 'confirmation'):
        if phase == 'confirmation':
            # A predeclared screen only, never an acceptance rule. Confirm every
            # cell if any affected cell has a >=3% median and all pairs positive.
            promising = [r['cell'] for r in summary['primary'] if r['empty_prefix'] and
                         statistics.median(p['cps_change_pct'] for p in r['pairs']) >= 3 and
                         all(p['cps_change_pct'] > 0 for p in r['pairs'])]
            summary['promising_cells'] = promising
            if not promising:
                summary['confirmation_skipped'] = 'no affected cell passed the predeclared screen'
                break
        for producers, mode, empty_prefix in cells:
            stem = f'p{producers}-{mode}-empty{empty_prefix}'
            entry = dict(cell=stem, producers=producers, mode=mode, empty_prefix=empty_prefix, pairs=[])
            for index, order in enumerate(orders(phase == 'confirmation')):
                pair = dict(order=order)
                for variant in order:
                    name = f'{phase}-{stem}-pair{index}-{variant}'
                    server = str(getattr(args, variant))
                    config = dict(server=server, peer=str(args.peer), output=str(args.output / name),
                                  mode=mode, empty_prefix=empty_prefix,
                                  client_cpus=client_cpus(rows, producers),
                                  count=args.empty_connections if empty_prefix else args.ordinary_connections,
                                  warmup=args.warmup, timeout=args.timeout,
                                  inputs={p: inputs[p] for p in (server, str(args.peer))},
                                  parent_namespace=os.readlink('/proc/self/ns/net'))
                    pair[variant] = launch(config, args.output / (name + '.json'))
                pair.update(comparison(pair))
                entry['pairs'].append(pair)
                print(json.dumps(dict(phase=phase, cell=stem, pair=index, **pair)), flush=True)
            entry['median_cps_change_pct'] = statistics.median(p['cps_change_pct'] for p in entry['pairs'])
            summary[phase].append(entry)
            save(args.output / f'{phase}-{stem}-summary.json', entry)
    c.require(inputs == {p: digest(p) for p in inputs}, 'campaign binary changed')
    save(args.output / 'summary.json', summary)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--trial':
        trial(json.loads(Path(sys.argv[2]).read_text()))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        for name in ('baseline', 'candidate', 'peer', 'output'):
            parser.add_argument(name, type=lambda s: Path(s).resolve())
        parser.add_argument('--empty-connections', type=int, default=512)
        parser.add_argument('--ordinary-connections', type=int, default=4096)
        parser.add_argument('--warmup', type=int, default=16)
        parser.add_argument('--timeout', type=float, default=120)
        campaign(parser.parse_args())
