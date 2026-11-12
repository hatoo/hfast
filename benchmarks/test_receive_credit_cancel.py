import unittest
from receive_credit_cancel import HALF, datagram_receipts, encode, frames, headers


class WireTests(unittest.TestCase):
    def test_exact_datagram_receipts_include_the_final_close(self):
        report=dict(sent_datagrams_before_close=32,received_datagrams=17,gso_segment_excess=7)
        datagram_receipts(report,dict(InDatagrams=43))
        for actual in (42,44):
            with self.assertRaisesRegex(ValueError,'UDP datagram receipt mismatch'):
                datagram_receipts(report,dict(InDatagrams=actual))

    def test_ack_holes_remain_holes(self):
        values=[(2,[(101,105),(0,99)])]
        self.assertEqual(list(frames(bytes.fromhex(encode(values)))),values)

    def test_sparse_bytes_and_reset_final_size_are_distinct(self):
        values=[(0x0e,(256,HALF-1,False,b'x')),(4,(256,0x10c,HALF)),(0x11,(256,3*HALF))]
        self.assertEqual(list(frames(bytes.fromhex(encode(values)))),values)
        self.assertEqual(len(values[0][1][3]),1)

    def test_ack_underflow_is_rejected(self):
        for value in [b'\x02\x01\x00\x00\x02',b'\x02\x01\x00\x01\x00\x01\x00']:
            with self.assertRaisesRegex(ValueError,'invalid ACK'):
                list(frames(value))

    def test_unsupported_frame_and_truncated_integer_fail(self):
        for value in [b'\xff',b'\x05\x00\x00',b'\x11\xff']:
            with self.assertRaises(ValueError):list(frames(value))

    def test_independent_post_and_get_headers(self):
        from aioquic.buffer import Buffer
        for method,code in [(b'POST',b'\xd4'),(b'GET',b'\xd1')]:
            block=b'\x00\x00'+code+b'\xd7\x50\x09localhost\xc1'
            b=Buffer(capacity=100)
            b.push_uint_var(1);b.push_uint_var(len(block));b.push_bytes(block)
            if method==b'POST':
                b.push_uint_var(0);b.push_uint_var(HALF-23)
            headers(b.data,method,0)
            with self.assertRaisesRegex(ValueError,'wrong HTTP headers'):
                headers(b.data,b'GET' if method==b'POST' else b'POST',0)


class SustainedTests(unittest.TestCase):
    @staticmethod
    def report():
        from receive_credit_cancel import INITIAL_DATA
        count=16; total=3
        rows=[dict(first_stream_id=i*72,cancellation_cohort_ns=1000,cycle_ns=5000,
                   sent_through=20*(i+1),received_through=30*(i+1),
                   flow_control_bytes=5+(i+1)*(count*HALF+36),
                   advertised_stream_limit=48+18*i,advertised_data_limit=INITIAL_DATA)
              for i in range(total)]
        return dict(cohort=count,mode='inline',iterations=total,warmup=1,measured=2,
            cycles=rows,responses=6,cancelled=48,resets=48,errors=0,reset_final_size=HALF,
            reset_final_bytes=48*HALF,aborted_wire_bytes=1200,prefix_bytes=23,
            request_bytes=108,flow_control_bytes=5+3*(16*HALF+36),
            initial_stream_limit=32,advertised_stream_limit=84,advertised_data_limit=INITIAL_DATA,
            timing_qualified=False,manual_sparse_driver=True,max_packet_history=20,
            cancellation_stream_ids=[i*72+j*4 for i in range(3) for j in range(16)],
            response_stream_ids=[i*72+j*4 for i in range(3) for j in (16,17)],
            cancellation_latency_ns=[100]*48,response_latency_ns=[200]*6,
            interval=dict(start_monotonic_ns=10,end_monotonic_ns=20000,elapsed_ns=19990,cpu_elapsed_ns=300))

    def test_complete_cumulative_receipts(self):
        from receive_credit_cancel import verify_report
        row=verify_report(self.report())
        self.assertEqual(row['retired'],54)
        self.assertEqual(row['wire_bytes'],1313)

    def test_every_later_cohort_is_checked(self):
        from receive_credit_cancel import verify_report
        mutations=[('first_stream_id',0),('flow_control_bytes',5),('advertised_stream_limit',48),
                   ('advertised_data_limit',1),('sent_through',20),('received_through',30),
                   ('cancellation_cohort_ns',1),('cycle_ns',1)]
        for key,value in mutations:
            with self.subTest(key=key):
                report=self.report();report['cycles'][-1][key]=value
                with self.assertRaises(ValueError):verify_report(report)

    def test_lost_duplicate_and_misassociated_samples_fail(self):
        from receive_credit_cancel import verify_report
        for key in ('cancellation_latency_ns','response_latency_ns','cancellation_stream_ids','response_stream_ids'):
            row=self.report();row[key].pop()
            with self.assertRaisesRegex(ValueError,'missing/invalid samples'):verify_report(row)
        for key in ('cancellation_stream_ids','response_stream_ids'):
            row=self.report();row[key][-1]=row[key][0]
            with self.assertRaisesRegex(ValueError,'missing/duplicate'):verify_report(row)

    def test_bounds_phase_reset_credit_and_sparse_byte_faults_fail(self):
        from receive_credit_cancel import verify_report
        for key,value in [('iterations',8193),('warmup',3),('measured',3),('max_packet_history',129),
                          ('aborted_wire_bytes',48*HALF),('flow_control_bytes',16*HALF),
                          ('cancelled',16),('resets',47),('responses',5),('timing_qualified',True)]:
            row=self.report();row[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):verify_report(row)


class ProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util
        from pathlib import Path
        spec=importlib.util.spec_from_file_location('controller',Path(__file__).with_name('check-receive-credit-cancel.py'))
        cls.controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.controller)

    def test_producer_exit_malformed_and_stall_fail(self):
        import subprocess,sys
        for code in ['pass', 'print("bad-json")', 'import time;time.sleep(1)']:
            process=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE)
            try:
                with self.subTest(code=code),self.assertRaises((ValueError,TimeoutError)):
                    self.controller.line(process,.05)
            finally:
                if process.poll() is None:process.terminate()
                process.wait();process.stdout.close()

    def test_only_one_complete_report_is_accepted(self):
        import subprocess,sys
        for payload,valid in [('{}\n',True),('{}\n{}\n',False)]:
            process=subprocess.Popen([sys.executable,'-c','import sys;sys.stdout.write('+repr(payload)+')'],stdout=subprocess.PIPE)
            try:
                if valid:self.assertEqual(self.controller.line(process,1),{})
                else:
                    with self.assertRaisesRegex(ValueError,'extra peer output'):self.controller.line(process,1)
            finally:process.wait();process.stdout.close()


if __name__=='__main__':unittest.main()
