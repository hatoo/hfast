import io
import subprocess
import sys
import unittest

import crypto_churn as c


def report():
    epochs = []
    for size in (257, 36):
        ranges = c.schedule('overlap-duplicates', size)
        epochs.append(dict(bytes=size, schedule=ranges, original_hex='00' * size,
                           sent=[dict(packet=i * 2, start=a, stop=b)
                                 for i, (a, b) in enumerate(ranges)]))
    packets, size = c.validate_epochs(epochs, 'overlap-duplicates')
    return dict(phase='done', failed=0, offered=2, completed=2, requests=2,
                responses=2, tls_completed=2, close_sent=2, latencies_ns=[123, 456],
                seconds=.1, epochs=epochs, crypto_packets=packets * 2, crypto_bytes=size * 2)


class Oracles(unittest.TestCase):
    def test_valid_report(self):
        c.validate_done(report(), 'overlap-duplicates', 2)

    def test_rejects_missing_duplicate_failed_and_incomplete_work(self):
        for key in ('offered', 'completed', 'requests', 'responses', 'tls_completed', 'close_sent'):
            for delta in (-1, 1):
                row = report()
                row[key] += delta
                with self.subTest(key=key, delta=delta), self.assertRaises(RuntimeError):
                    c.validate_done(row, 'overlap-duplicates', 2)
        row = report()
        row['failed'] = 1
        with self.assertRaises(RuntimeError):
            c.validate_done(row, 'overlap-duplicates', 2)

    def test_rejects_latency_omission_and_bad_elapsed(self):
        for key, value in [('latencies_ns', [1]), ('latencies_ns', [0, 1]),
                           ('seconds', float('nan')), ('seconds', 0)]:
            row = report()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                c.validate_done(row, 'overlap-duplicates', 2)

    def test_rejects_schedule_and_packet_replay(self):
        row = report()
        row['epochs'][0]['sent'][1]['packet'] = 0
        with self.assertRaises(RuntimeError):
            c.validate_done(row, 'overlap-duplicates', 2)
        row = report()
        row['epochs'][1]['sent'].pop()
        with self.assertRaises(RuntimeError):
            c.validate_done(row, 'overlap-duplicates', 2)
        row = report()
        row['crypto_bytes'] -= 1
        with self.assertRaises(RuntimeError):
            c.validate_done(row, 'overlap-duplicates', 2)

    def collect_process(self, code, phase='ready', maximum=1024, timeout=2):
        process = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE)
        worker = dict(process=process, log=io.BytesIO(), buffer=b'')
        try:
            return c.collect([worker], phase, timeout, maximum)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()

    def test_collect_rejects_worker_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'failed/wrong phase'):
            self.collect_process("print('{\"phase\":\"failed\",\"failed\":1}')")

    def test_collect_accepts_complete_report(self):
        self.assertEqual(self.collect_process("print('{\"phase\":\"ready\"}')"),
                         [dict(phase='ready')])

    def test_collect_rejects_eof_and_partial_line(self):
        with self.assertRaisesRegex(RuntimeError, 'exited'):
            self.collect_process('pass')
        with self.assertRaisesRegex(RuntimeError, 'timeout'):
            self.collect_process("import sys,time; sys.stdout.write('{'); sys.stdout.flush(); time.sleep(5)", timeout=.2)

    def test_collect_rejects_oversize_and_duplicate_reports(self):
        with self.assertRaisesRegex(RuntimeError, 'oversized'):
            self.collect_process("print('x'*100)", maximum=10)
        with self.assertRaisesRegex(RuntimeError, 'duplicate'):
            self.collect_process("import os; os.write(1,b'{\"phase\":\"ready\"}\\n{\"phase\":\"ready\"}\\n')")


if __name__ == '__main__':
    unittest.main()
