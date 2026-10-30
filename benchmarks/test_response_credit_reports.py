"""Corrupt a complete independently assembled transcript, never native structs."""
import copy
import unittest
from response_credit_reports import RESPONSE, validate


def complete():
    return dict(phase='done', error=None, count=1, step=25, mode='each', completed=1,
        bootstrap_acked=True, control_bytes=3, fence_acked=True, unacked_work=0,
        udp=dict(status='available', drops=0),
        workload_start_ns=5, workload_end_ns=95,
        interval=dict(start_monotonic_ns=100, end_monotonic_ns=200, elapsed_ns=100, cpu_elapsed_ns=80),
        streams=[dict(id=0, limit=25, grant_acked=25, seen=(1 << 25)-1, fin=True, request_acked=True,
                      started_ns=10, completed_ns=30, latency_ns=20, frames=1, duplicates=0)],
        sent_work=[[1, 0, 3, 3, True, False], [2, 1, 0, 0, True, False], [3, 4, 0, 0, True, False]],
        acked_work=[[0, 3, 3], [1, 0, 0], [4, 0, 0]],
        frames=[[10, 3, 0, [0, 4, 0], False, 0], [11, 0, 0, list(RESPONSE), True, 0]],
        received_ranges=[[10, 11]], acked_packet_ranges=[[10, 11]], server_ack_ranges=[[1, 3]],
        withheld_ranges=[], retries=0, dropped_response_packets=0, dropped_grants=0,
        duplicate_packets=0, replayed=False, max_ack_ranges=1)


class Reports(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(validate(complete(), 1, 25, 'each')['latency_samples'], 1)

    def test_accounting_mutations(self):
        for key, value in [('phase', 'failed'), ('error', 'bad'), ('completed', 2), ('count', 2),
                           ('fence_acked', False), ('unacked_work', 1), ('bootstrap_acked', False),
                           ('control_bytes', 2), ('acked_packet_ranges', []), ('server_ack_ranges', [])]:
            with self.subTest(key=key):
                row = complete()
                row[key] = value
                with self.assertRaises(ValueError): validate(row, 1, 25, 'each')

    def test_stream_sample_mutations(self):
        for key, value in [('seen', 0), ('fin', False), ('request_acked', False), ('id', 4),
                           ('grant_acked', 24), ('limit', 24), ('latency_ns', None), ('latency_ns', 21),
                           ('latency_ns', -1), ('completed_ns', None), ('started_ns', None),
                           ('frames', 2), ('duplicates', 1)]:
            with self.subTest(key=key, value=value):
                row = complete()
                row['streams'][0][key] = value
                with self.assertRaises(ValueError): validate(row, 1, 25, 'each')

    def test_corrupt_overlap_missing_interval_fin_and_extra_stream(self):
        for fault in ('byte', 'interval', 'fin', 'extra', 'control', 'duplicate', 'early-fin'):
            row = complete()
            if fault == 'byte': row['frames'][1][3][12] ^= 1
            if fault == 'interval': row['frames'][1][2], row['frames'][1][3] = 1, list(RESPONSE[1:])
            if fault == 'fin': row['frames'][1][4] = False
            if fault == 'extra': row['frames'][1][1] = 4
            if fault == 'control': row['frames'].pop(0)
            if fault == 'duplicate': row['frames'].append(copy.deepcopy(row['frames'][1]))
            if fault == 'early-fin': row['frames'][1][3] = list(RESPONSE[:1])
            with self.subTest(fault=fault), self.assertRaises(ValueError): validate(row, 1, 25, 'each')

    def test_generation_and_retry_mutants(self):
        for fault in ('missing', 'duplicate', 'retry', 'grant', 'ack', 'unsent-ack'):
            row = complete()
            if fault == 'missing': row['sent_work'].pop(1)
            if fault == 'duplicate': row['sent_work'].insert(1, row['sent_work'][0].copy())
            if fault == 'retry': row['sent_work'][1][-1] = True
            if fault == 'grant': row['sent_work'][1][1] = 2
            if fault == 'ack': row['acked_work'].append([1, 0, 0])
            if fault == 'unsent-ack': row['sent_work'][1][4] = False
            with self.subTest(fault=fault), self.assertRaises(ValueError): validate(row, 1, 25, 'each')

    def test_missing_or_nonzero_drop_evidence(self):
        for udp in (dict(status='unavailable', drops=None), dict(status='available', drops=1)):
            row = complete()
            row['udp'] = udp
            with self.assertRaises(ValueError): validate(row, 1, 25, 'each')


if __name__ == '__main__': unittest.main()
