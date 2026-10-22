import copy
import unittest

import persistent_peers as p


def report(phase='reported'):
    return dict(phase=phase, failed=0, peers=[dict(port=10000+i, tls_completed=True,
        requests=4, responses=4, next_stream=16, fences=2, pending_acks=0,
        pending_responses=0, close_sent=False, sent_datagrams=12,
        received_datagrams=10, latencies_ns=[10, 20, 30, 40]) for i in range(128)])


class Oracles(unittest.TestCase):
    def validate(self, row):
        p.validate_peers(row, 'reported', 128, 2, 2, samples=True)

    def test_all_128_individual_peers_pass(self):
        self.validate(report())

    def test_one_peer_cannot_compensate_for_another(self):
        for key in ('requests', 'responses', 'next_stream', 'fences'):
            row = report()
            row['peers'][0][key] += 1
            row['peers'][-1][key] -= 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(row)

    def test_incomplete_tls_pending_acks_and_missing_latencies_fail(self):
        for key, value in [('tls_completed', False), ('pending_acks', 1),
                           ('pending_responses', 1), ('close_sent', True),
                           ('latencies_ns', [10, 20, 30]), ('latencies_ns', [10, 20, 30, 0]),
                           ('latencies_ns', [10, 20, 30, True])]:
            row = report()
            row['peers'][-1][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(row)

    def test_omitted_duplicated_and_replaced_peers_fail(self):
        row = report()
        row['peers'].pop()
        with self.assertRaisesRegex(RuntimeError, 'missing/extra'):
            self.validate(row)
        row = report()
        row['peers'][-1]['port'] = row['peers'][0]['port']
        with self.assertRaisesRegex(RuntimeError, 'shared'):
            self.validate(row)
        old = report('ready')
        for peer in old['peers']:
            peer.update(fences=1, sent_datagrams=9)
        row = report()
        row['peers'][-1]['port'] = 20000
        with self.assertRaisesRegex(RuntimeError, 'replaced'):
            p.validate_peers(row, 'reported', 128, 2, 2, old)

    def test_fences_have_exact_datagram_accounting(self):
        old = report('ready')
        for peer in old['peers']:
            peer.update(fences=1, sent_datagrams=9)
        row = report()
        p.validate_peers(row, 'reported', 128, 2, 2, old)
        row['peers'][-1]['sent_datagrams'] += 1
        with self.assertRaisesRegex(RuntimeError, 'datagram count'):
            p.validate_peers(row, 'reported', 128, 2, 2, old)

    def test_close_requires_each_close_and_no_late_traffic(self):
        old = report()
        row = copy.deepcopy(old)
        row['phase'] = 'closed'
        for peer in row['peers']:
            peer.update(close_sent=True, sent_datagrams=13)
        p.validate_peers(row, 'closed', 128, 2, 2, old)
        row['peers'][-1]['received_datagrams'] += 1
        with self.assertRaisesRegex(RuntimeError, 'traffic after'):
            p.validate_peers(row, 'closed', 128, 2, 2, old)

    def test_small_timing_report_must_match_requested_work(self):
        good = dict(phase='done', failed=0, peers=128, requests=1024, responses=1024, seconds=1.)
        p.validate_done(good, 128, 8, 1)
        for key, value in [('failed', 1), ('peers', 127), ('requests', 1023),
                           ('responses', 1023), ('seconds', 0), ('seconds', float('nan'))]:
            row = dict(good, **{key: value})
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                p.validate_done(row, 128, 8, 1)


if __name__ == '__main__':
    unittest.main()
