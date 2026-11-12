#!/usr/bin/env python3
"""Bounded sustained native cancellation audit/timing; run in a private netns."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import time

import udp_accounting as udp
from receive_credit_cancel import datagram_receipts, frames, negative_controls, require, verify, verify_report


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def line(process, timeout=150):
    deadline = time.monotonic()+timeout
    data = bytearray()
    while time.monotonic() < deadline:
        if not select.select([process.stdout], [], [], max(0,deadline-time.monotonic()))[0]:
            break
        byte = os.read(process.stdout.fileno(),65536)
        require(byte, f'peer exited {process.poll()} before report')
        data.extend(byte)
        require(len(data)<128_000_000, 'oversized report')
        if b'\n' in byte:
            require(data.count(b'\n')==1 and data[-1:]==b'\n','unexpected extra peer output')
            return json.loads(data)
    raise TimeoutError('peer report deadline')


def process_metrics(pid):
    proc=Path(f'/proc/{pid}')
    fields=(proc/'stat').read_text().rsplit(') ',1)[1].split()
    values={}
    for row in (proc/'smaps_rollup').read_text().splitlines()[1:]:
        key,_,rest=row.partition(':')
        if rest.strip().endswith(' kB'):values[key]=int(rest.split()[0])
    return dict(pid=pid,start_ticks=int(fields[19]),user_ticks=int(fields[11]),
                system_ticks=int(fields[12]),ticks_per_second=os.sysconf('SC_CLK_TCK'),
                rss_kb=values['Rss'],pss_kb=values['Pss'],anonymous_kb=values['Anonymous'])


def run(server_binary, peer_binary, out, count, mode, warmup=1, cycles=1, timed=False,
        server_cpu=2,peer_cpu=4):
    out.mkdir(parents=True,exist_ok=False)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1',0))
        port=s.getsockname()[1]
    require(warmup>0 and cycles>0 and warmup+cycles<=8192,'invalid cycle budget')
    require(timed or warmup+cycles<=64,'wire audit too large')
    require(server_cpu!=peer_cpu and {server_cpu,peer_cpu}<=os.sched_getaffinity(0),'invalid affinity')
    server_cmd=['taskset','-c',str(server_cpu),str(server_binary),'--tcp','0','--quic',str(port),'--threads','1','--max-streams',str(2*count)]
    peer_cmd=['taskset','-c',str(peer_cpu),str(peer_binary),str(port),str(count),mode,str(warmup),str(cycles)]
    (out/'commands.json').write_text(json.dumps(dict(server=server_cmd,peer=peer_cmd),indent=2)+'\n')
    net_before=udp.namespace_snapshot()
    server=peer=None
    raw=dict(cohort=count,mode=mode,namespace_before=net_before,timing=timed,warmup=warmup,cycles=cycles,server_cpu=server_cpu,peer_cpu=peer_cpu)
    error=None
    with (out/'server.log').open('x') as server_log, (out/'peer.stderr').open('x') as peer_log:
        try:
            server=subprocess.Popen(server_cmd,stdout=server_log,stderr=server_log)
            deadline=time.monotonic()+5
            while True:
                require(server.poll() is None,'server startup failed')
                before=udp.process_snapshot(server.pid,port,1)
                if before['status']=='available':break
                require(time.monotonic()<deadline,'server socket readiness timeout')
                time.sleep(.01)
            raw['server_before']=before
            peer=subprocess.Popen(peer_cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=peer_log,
                                  env={k:v for k,v in os.environ.items() if k!='STOP_BATCH_TRACE'} | ({} if timed else {'STOP_BATCH_TRACE':str(out/'wire.jsonl')}))
            ready=line(peer)
            require(ready['event']=='ready','missing readiness')
            raw['ready']=ready
            peer_before=udp.process_snapshot(peer.pid,ready['port'],1)
            raw['peer_before']=peer_before
            require(peer_before['status']=='available' and all(s['drops']==0 for s in peer_before['sockets']),
                    'peer initial socket evidence unavailable/dirty')
            peer.stdin.write(b'warmup\n');peer.stdin.flush()
            warmed=line(peer)
            require(warmed==dict(event='warmed',cycles=warmup,cancelled=warmup*count,
                    responses=2*warmup,next_stream=warmup*(count+2)*4),'wrong warmup accounting')
            raw['warmed']=warmed
            raw['metrics_before']={key:process_metrics(proc.pid) for key,proc in [('server',server),('peer',peer)]}
            peer.stdin.write(b'start\n');peer.stdin.flush()
            report=line(peer)
            raw['metrics_after']={key:process_metrics(proc.pid) for key,proc in [('server',server),('peer',peer)]}
            (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            require(report['mode']==mode and report['cohort']==count and report['warmup']==warmup and report['measured']==cycles,'wrong producer workload')
            raw['verification']=verify_report(report)
            if not timed:
                records=[json.loads(row) for row in (out/'wire.jsonl').read_text().splitlines()]
                (out/'fenced-wire.json').write_text(json.dumps(records,indent=2)+'\n')
                raw['verification']=verify(records,report)
                raw['negative_controls']=negative_controls(records,report)
            raw['server_after']=udp.process_snapshot(server.pid,port,1)
            raw['peer_after']=udp.process_snapshot(peer.pid,ready['port'],1)
            raw['server_delta']=udp.process_delta(before,raw['server_after'])
            raw['peer_delta']=udp.process_delta(peer_before,raw['peer_after'])
            for key in ('server_delta','peer_delta'):
                require(raw[key]['status']=='available' and raw[key]['drops']==0,f'{key} unavailable/dirty')
            peer.stdin.write(b'exit\n');peer.stdin.flush()
            require(peer.wait(timeout=5)==0,'peer close failed')
            time.sleep(.02)
            raw['namespace_after']=udp.namespace_snapshot()
            raw['namespace_delta']=udp.namespace_delta(net_before,raw['namespace_after'])
            delta=raw['namespace_delta']
            require(delta['status']=='available','namespace evidence unavailable')
            for key in ('InErrors','RcvbufErrors','SndbufErrors','InCsumErrors','NoPorts'):
                require(delta['counters'].get(key)==0,f'UDP {key}')
            datagram_receipts(report,delta['counters'])
            require(server.poll() is None,'server exited unexpectedly')
        except Exception as exc:
            error=f'{type(exc).__name__}: {exc}'
        finally:
            for process in (peer,server):
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill();process.wait(timeout=5)
            raw['exit_codes']={key:process.returncode if process is not None else None
                               for key,process in [('server',server),('peer',peer)]}
            raw['error']=error
            (out/'evidence.json').write_text(json.dumps(raw,indent=2)+'\n')
    rows=[json.loads(row.split(' ',1)[1]) for row in (out/'server.log').read_text().splitlines()
          if row.startswith('C411_CREDIT ')]
    batches=[json.loads(row.split(' ',1)[1]) for row in (out/'server.log').read_text().splitlines()
             if row.startswith('C411_RX ')]
    coverage=dict(status='available' if rows else 'unavailable',objects=rows,
                  peak=max((r['peak'] for r in rows),default=None),
                  max_receive_datagrams=max((r['datagrams'] for r in batches),default=None),
                  **{key:sum(r[key] for r in rows) if rows else None for key in
                     ('pushes','terminal_cancellations','cancel_visits','writes','ack_cancellations','ack_visits')})
    require(not timed or not rows,'observer server is ineligible for timing')
    if rows and error is None:
        accepted=[json.loads(row.split(' ',1)[1]) for row in (out/'server.log').read_text().splitlines()
                  if row.startswith('C411_RECEIVE ')]
        expected=[]
        for row in records:
            if row['direction']!='tx':continue
            for ty,v in frames(bytes.fromhex(row['hex'])):
                if 8<=ty<=15:
                    sid,offset,fin,data=v
                    expected.append(dict(id=sid,size=offset+len(data),final=fin))
                elif ty==4:
                    expected.append(dict(id=v[0],size=v[2],final=True))
        require(accepted==expected,'observer and wire receive accounting differ')
        require(all(r['remaining_streams']==0 for r in rows),'observer credit state not retired')
        coverage['accepted_receive_updates']=len(accepted)
        segments=sum(r['datagrams'] for r in batches)
        messages=sum(r['messages'] for r in batches)
        require(segments==report['sent_datagrams_before_close']+1, 'observer segment receipt mismatch')
        require(segments-messages==report['gso_segment_excess'], 'observer GRO accounting mismatch')
        require(messages+report['received_datagrams']==raw['namespace_delta']['counters']['InDatagrams'],
                'observer namespace receipt mismatch')
        coverage.update(receive_segments=segments,receive_messages=messages)
    (out/'coverage.json').write_text(json.dumps(coverage,indent=2)+'\n')
    require(error is None,error)
    return dict(cohort=count,mode=mode,verification=raw['verification'],coverage=coverage,errors=0,timing=timed,interval=report['interval'])


def main(args):
    outer = os.environ.get('CANCELLATION_PARENT_NETNS')
    require(outer and os.readlink('/proc/self/ns/net') != outer, 'private network namespace required')
    args.output.mkdir(parents=True,exist_ok=False)
    inputs={key:sha(getattr(args,key)) for key in ('server','peer')}
    rows=[]
    for count in args.cohorts:
        for mode in args.modes:
            row=run(args.server,args.peer,args.output/f'{mode}-{count}',count,mode,args.warmup,args.cycles,args.timed,args.server_cpu,args.peer_cpu)
            rows.append(row)
            print(json.dumps(dict(cohort=count,mode=mode,peak=row['coverage']['peak'],
                                  cancellations=row['coverage']['terminal_cancellations'],
                                  ack_cancellations=row['coverage']['ack_cancellations'],errors=0)),flush=True)
    require(inputs=={key:sha(getattr(args,key)) for key in inputs},'binary changed')
    (args.output/'summary.json').write_text(json.dumps(dict(inputs=inputs,cases=rows,timing=args.timed),indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('server','peer','output'):
        p.add_argument(key,type=lambda v:Path(v).resolve())
    p.add_argument('--cohorts',nargs='+',type=int,choices=[16,64,256],default=[16,64,256])
    p.add_argument('--modes',nargs='+',choices=['inline','separate','survivors','late-ack'],
                   default=['inline','separate','survivors','late-ack'])
    p.add_argument('--warmup',type=int,default=1)
    p.add_argument('--cycles',type=int,default=1)
    p.add_argument('--timed',action='store_true')
    p.add_argument('--server-cpu',type=int,default=2)
    p.add_argument('--peer-cpu',type=int,default=4)
    main(p.parse_args())
