import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import crypto_campaign as campaign
import crypto_churn as c


def fixture():
    config = dict(mode='normal', empty_prefix=512, count=2, warmup=1, client_cpus=[2],
                  parent_namespace='net:[1]', inputs={'server': 'abc', 'peer': 'def'})
    epochs = []
    for size in (246, 36):
        ranges = c.schedule('normal', size, 512)
        epochs.append(dict(bytes=size, empty_prefix=512, schedule=ranges, original_hex='00' * size,
                           sent=[dict(packet=i, start=a, stop=b) for i, (a, b) in enumerate(ranges)],
                           empty_acked=list(range(512))))
    packets, size = c.validate_epochs(epochs, 'normal', 512)
    worker = dict(phase='done', failed=0, offered=2, completed=2, requests=2, responses=2,
                  tls_completed=2, close_sent=2, latencies_ns=[10, 100], seconds=1,
                  empty_prefix=512, empty_crypto_packets=2048, empty_crypto_acked=2048,
                  epochs=epochs, crypto_packets=2 * packets, crypto_bytes=2 * size)
    obs = dict(status='available', delta=dict(drops=0), snapshot=dict(sockets=[
        dict(drops=0, diag_drops=0, rx_queue=0, tx_queue=0)]))
    before = dict.fromkeys(c.ERROR_COUNTERS, 0) | dict(InDatagrams=0)
    affinity = dict(server={'10': [0]}, peers=[{'11': [2]}])
    row = dict(mode='normal', empty_prefix=512, client_cpus=[2], warmup=1, gro=True,
               shared_namespace=False, smoke=False, network_namespace='net:[2]',
               inputs=config['inputs'].copy(), errors=0, completed=2, per_producer=2,
               producers=1, workers=[worker], ready=[dict(warmup=1, port=1234)],
               final=[dict(phase='validated', retirement_probes=1, replacements_verified=3,
                           maximum_server_addresses=1, port=1234, failed=0,
                           ledger=dict(sent_datagrams=10, received_datagrams=20))],
               udp_before=before, udp_after=before | dict(InDatagrams=30),
               socket_audit=dict(before=[copy.deepcopy(obs) for _ in range(2)],
                                 after=[copy.deepcopy(obs) for _ in range(2)]),
               affinity_before=copy.deepcopy(affinity), affinity_after=copy.deepcopy(affinity),
               seconds=2, server_cpu=dict(user=.5, system=.5, cores=.5),
               peer_cpu=[dict(user=.2, system=.1, cores=.15)])
    return row, config


class CampaignTests(unittest.TestCase):
    def test_qualified_accounting_and_all_latency_samples(self):
        row, config = fixture()
        campaign.audit(row, config)
        self.assertEqual(campaign.metrics(row)['samples'], 2)
        self.assertEqual(campaign.metrics(row)['p99_ns'], 100)

    def test_missing_ack_real_bytes_or_latency_is_rejected(self):
        for fault in ('ack', 'bytes', 'sample', 'response'):
            row, config = fixture()
            worker = row['workers'][0]
            if fault == 'ack':
                worker['epochs'][1]['empty_acked'].pop()
            elif fault == 'bytes':
                worker['crypto_bytes'] -= 1
            elif fault == 'sample':
                worker['latencies_ns'].pop()
            else:
                worker['responses'] -= 1
            with self.subTest(fault=fault), self.assertRaises(RuntimeError):
                campaign.audit(row, config)

    def test_rejects_missing_producer_final_close_and_error_counters(self):
        for fault in ('worker', 'close', 'udp', 'final'):
            row, config = fixture()
            if fault == 'worker':
                row['workers'].clear()
            elif fault == 'close':
                row['udp_after']['InDatagrams'] -= 1
            elif fault == 'udp':
                row['udp_after']['InErrors'] += 1
            else:
                row['final'][0]['retirement_probes'] = 0
            with self.subTest(fault=fault), self.assertRaises(RuntimeError):
                campaign.audit(row, config)

    def test_drop_queue_and_affinity_fail_even_with_complete_responses(self):
        for fault in ('drop', 'diag', 'queue', 'server', 'peer'):
            row, config = fixture()
            if fault == 'server':
                row['affinity_after']['server']['10'] = [0, 2]
            elif fault == 'peer':
                row['affinity_before']['peers'][0]['11'] = [0]
            elif fault == 'drop':
                row['socket_audit']['after'][0]['delta']['drops'] = 1
            else:
                key = 'diag_drops' if fault == 'diag' else 'rx_queue'
                row['socket_audit']['after'][0]['snapshot']['sockets'][0][key] = 1
            with self.subTest(fault=fault), self.assertRaises(RuntimeError):
                campaign.audit(row, config)

    def test_refuses_shared_namespace_changed_binary_and_workload(self):
        for key, value in [('network_namespace', 'net:[1]'), ('shared_namespace', True),
                           ('inputs', {}), ('client_cpus', [3]), ('empty_prefix', 0),
                           ('gro', False), ('smoke', True)]:
            row, config = fixture()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                campaign.audit(row, config)

    def test_physical_pools_disjoint_even_when_clients_share(self):
        topology = [dict(cpu=i, core=i // 2, socket=0) for i in range(8)]
        self.assertEqual(campaign.client_cpus(topology, 1), [2])
        self.assertEqual(campaign.client_cpus(topology, 4), [2, 4, 6, 2])
        with self.assertRaises(RuntimeError):
            campaign.client_cpus(topology[:2], 1)

    def test_opposite_order_confirmation_and_paired_percentages(self):
        self.assertEqual(campaign.orders(), [['baseline', 'candidate'],
                         ['candidate', 'baseline'], ['baseline', 'candidate']])
        self.assertEqual(campaign.orders(True), [p[::-1] for p in campaign.orders()])
        row, _ = fixture()
        base = campaign.metrics(row)
        candidate = base | dict(cps=2 * base['cps'], server_cpu_ns=.5 * base['server_cpu_ns'])
        changes = campaign.comparison(dict(baseline=base, candidate=candidate))
        self.assertEqual(changes['cps_change_pct'], 100)
        self.assertEqual(changes['server_cpu_ns_change_pct'], -50)

    def test_fresh_namespace_dispatch_failure_preserves_command_and_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            config = dict(output=str(Path(directory) / 'trial'))
            with patch.object(campaign.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['unshare'])) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    campaign.launch(config, path)
            self.assertEqual(run.call_args.args[0][:2], ['unshare', '--net'])
            self.assertEqual(json.loads(path.read_text()), config)
            self.assertTrue(path.with_suffix('.stderr').exists())
            self.assertFalse((Path(config['output']) / 'result.json').exists())
            with self.assertRaises(FileExistsError):
                campaign.save(path, config)

    def test_trial_refuses_callers_namespace_before_starting_processes(self):
        with patch.object(campaign.os, 'readlink', return_value='net:[1]'):
            with self.assertRaisesRegex(RuntimeError, 'fresh namespace'):
                campaign.trial(dict(parent_namespace='net:[1]'))


if __name__ == '__main__':
    unittest.main()
