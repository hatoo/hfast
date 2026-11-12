#!/usr/bin/env python3
"""Fixed-work native comparison; run each order in its own private netns."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path

from receive_credit_cancel import require

spec=importlib.util.spec_from_file_location('cancel_controller',Path(__file__).with_name('check-receive-credit-cancel.py'))
controller=importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


def main(args):
    outer=os.environ.get('CANCELLATION_PARENT_NETNS')
    require(outer and os.readlink('/proc/self/ns/net')!=outer,'private network namespace required')
    require(args.order and len(args.order)<=16 and set(args.order)=={'A','B'},'invalid order')
    require(args.baseline!=args.candidate,'comparison requires distinct candidates')
    args.output.mkdir(parents=True,exist_ok=False)
    paths={'A':args.baseline,'B':args.candidate,'peer':args.peer}
    hashes={key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in paths.items()}
    rows=[]
    for i,variant in enumerate(args.order):
        out=args.output/f'{i:02}-{variant}'
        result=controller.run(paths[variant],args.peer,out,args.cohort,args.mode,
                              args.warmup,args.cycles,True,args.server_cpu,args.peer_cpu)
        evidence=json.loads((out/'evidence.json').read_text())
        interval=result['interval']
        metrics={}
        for component in ('server','peer'):
            before=evidence['metrics_before'][component];after=evidence['metrics_after'][component]
            require(before['pid']==after['pid'] and before['start_ticks']==after['start_ticks'], 'process changed')
            hz=before['ticks_per_second']
            require(hz>0 and hz==after['ticks_per_second'],'invalid CPU tick rate')
            cpu={key:(after[key]-before[key])/hz for key in ('user_ticks','system_ticks')}
            require(all(x>=0 for x in cpu.values()),'CPU counter decreased')
            metrics[component]=dict(user_seconds=cpu['user_ticks'],system_seconds=cpu['system_ticks'],
                cpu_seconds=sum(cpu.values()),tick_uncertainty_seconds=2/hz,
                rss_kb_before=before['rss_kb'],rss_kb_after=after['rss_kb'],
                anonymous_kb_before=before['anonymous_kb'],anonymous_kb_after=after['anonymous_kb'])
        row=dict(index=i,variant=variant,cohort=args.cohort,mode=args.mode,warmup=args.warmup,
                 cycles=args.cycles,interval=interval,metrics=metrics,
                 cancellations_per_second=args.cycles*args.cohort*1e9/interval['elapsed_ns'],
                 verification=result['verification'])
        rows.append(row)
        (out/'measurement.json').write_text(json.dumps(row,indent=2)+'\n')
        print(json.dumps(row),flush=True)
    require(hashes=={key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in paths.items()},'binary changed')
    (args.output/'summary.json').write_text(json.dumps(dict(order=args.order,inputs=hashes,
        cases=rows,host_qualified=False,scope='native sparse abort cycles with two successful followups'),indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('baseline','candidate','peer','output'):p.add_argument(key,type=lambda v:Path(v).resolve())
    p.add_argument('--order',default='ABBAABBA')
    p.add_argument('--cohort',type=int,choices=[16,64,256],default=256)
    p.add_argument('--mode',choices=['inline','separate','survivors','late-ack'],default='inline')
    p.add_argument('--warmup',type=int,default=32)
    p.add_argument('--cycles',type=int,default=2048)
    p.add_argument('--server-cpu',type=int,default=2)
    p.add_argument('--peer-cpu',type=int,default=4)
    main(p.parse_args())
