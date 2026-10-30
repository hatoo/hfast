"""Handwritten two-wave transcript and negative accounting controls."""
import copy
import unittest
from response_credit_sustained_reports import validate
from response_credit_reports import RESPONSE


def complete():
    return dict(phase='done', error=None, count=4, window=2, schedule='two-fragment', mode='each',
        completed=4, retired=4, request_acks=4, response_bytes=100, grants=4, grant_acks=4,
        request_bytes_reserved=77, max_data=77, max_streams=4, max_flights=1,
        bootstrap_acked=True, control_bytes=3, fence_acked=True, unacked_work=0,
        udp=dict(status='available', drops=0), workload_start_ns=5, workload_end_ns=95,
        interval=dict(start_monotonic_ns=100, end_monotonic_ns=200, elapsed_ns=100, cpu_elapsed_ns=80),
        samples=[[0,10,20],[4,10,21],[8,30,40],[12,30,42]],
        trace=True, sent_work=[[1,0,3,3,True,False],*[ [2+i//2,1,i*4,0,True,False] for i in range(4)],
                              *[[4+i//2,2,i*4,25,True,False] for i in range(4)], [6,4,0,0,True,False]],
        acked_work=[[0,3,3],*[[1,i*4,0] for i in range(4)],*[[2,i*4,25] for i in range(4)],[4,0,0]],
        frames=[[10,3,0,[0,4,0],False,0],*[[11+i,i*4,0,list(RESPONSE),True,0] for i in range(4)]],
        received_ranges=[[10,14]], acked_packet_ranges=[[10,14]], server_ack_ranges=[[1,6]],
        withheld_ranges=[], retries=0, dropped_response_packets=0, dropped_grants=0,
        duplicate_packets=0, replayed=False, max_ack_ranges=1, sent_packets=6, ack_packets=1, received_packets=5)


def check(row): return validate(row,4,2,'two-fragment','each')


class Reports(unittest.TestCase):
    def test_exact_batched_generations(self):
        self.assertEqual(check(complete())['latency_samples'],4)

    def test_all_samples_retained_without_frame_transcript(self):
        row=complete()
        row.update(trace=False,sent_work=[],frames=[],acked_work=[])
        self.assertEqual(check(row)['response_bytes'],100)
        row['samples'].pop()
        with self.assertRaises(ValueError): check(row)

    def test_wave_identity_sample_and_timestamp_mutants(self):
        for i,field,value in ((2,0,0),(2,1,20),(0,2,10),(2,1,None),(3,2,100)):
            row=complete(); row['samples'][i][field]=value
            with self.subTest(i=i,field=field), self.assertRaises(ValueError): check(row)

    def test_credit_and_retirement_mutants(self):
        for key,value in (('max_data',76),('max_streams',3),('request_acks',3),('grants',3),
                          ('grant_acks',3),('retired',3),('response_bytes',99),('max_flights',65),
                          ('unacked_work',1),('fence_acked',False)):
            row=complete();row[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): check(row)

    def test_missing_packet_copies_or_grant_generations(self):
        for fault in ('request','grant','ack','duplicate','retry','unsent','wrong-grant','no-ack'):
            row=complete()
            if fault=='request': row['sent_work'].pop(1)
            if fault=='grant': row['sent_work'].pop(5)
            if fault=='ack': row['acked_work'].pop(1)
            if fault=='duplicate': row['acked_work'].append(row['acked_work'][1])
            if fault=='retry': row['sent_work'][1][-1]=True
            if fault=='unsent': row['sent_work'][1][4]=False
            if fault=='wrong-grant': row['sent_work'][5][3]=2
            if fault=='no-ack': row['server_ack_ranges']=[]
            with self.subTest(fault=fault), self.assertRaises(ValueError): check(row)

    def test_late_duplicate_validates_bytes_without_new_success(self):
        row=complete();row['frames'].append(copy.deepcopy(row['frames'][1]))
        self.assertEqual(check(row)['completed'],4)
        row['frames'][-1][3][0]^=1
        with self.assertRaises(ValueError): check(row)

    def test_missing_bytes_fin_and_drop_evidence(self):
        for fault in ('bytes','fin','drop','unavailable','ack'):
            row=complete()
            if fault=='bytes':row['frames'][1][3]=list(RESPONSE[:-1]);row['frames'][1][4]=False
            if fault=='fin':row['frames'][1][4]=False
            if fault=='drop':row['udp']['drops']=1
            if fault=='unavailable':row['udp']['status']='unavailable'
            if fault=='ack':row['acked_packet_ranges']=[]
            with self.subTest(fault=fault), self.assertRaises(ValueError):check(row)


if __name__=='__main__':unittest.main()
