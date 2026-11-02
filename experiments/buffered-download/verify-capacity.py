#!/usr/bin/env python3
"""Check the saved Alice/Bob download studies; standard library only."""
import argparse
import json
import math
from pathlib import Path
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('results', nargs='?', type=Path, default=Path(__file__).parent / 'results' / 'capacity')
root = parser.parse_args().results
reports = []
paths = sorted(root.glob('*.json'))
assert paths, 'no study files found'
for path in paths:
    x = json.loads(path.read_text())
    assert x['status'] in ('success', 'failed'), f'{path}: unfinished study'
    args = x['settings']
    trials = x['trials']
    for t in trials:
        n = args['packets']
        r = t['receiver']
        s = t['sender']
        assert s['packets'] == n
        assert 0 < r['unique'] <= n and r['invalid'] == r['duplicates'] == 0
        assert math.isclose(t['loss_percent'], 100 * (1-r['unique']/n), abs_tol=1e-10)
        window = max(s['send_seconds'], r['arrival_span_seconds'])
        assert math.isclose(t['delivery_window_seconds'], window, abs_tol=1e-10)
        assert math.isclose(t['delivered_payload_gbps'], r['unique']*args['payload']*8/1e9/window, rel_tol=1e-12)
        assert math.isclose(s['offered_payload_gbps'], n*args['payload']*8/1e9/s['send_seconds'], rel_tol=1e-12)
        if 'missing_per_100k_packets' in r:
            assert len(r['missing_per_100k_packets']) == (n+99_999)//100_000
            assert sum(r['missing_per_100k_packets']) == n-r['unique']
        if args.get('payload_receive_buffer_mib', 0):
            assert r['receive_buffer_bytes'] == 2*args['payload_receive_buffer_mib']*1024*1024
        if t['mode'] == 'gotatun' and not args['receive_buffer_mib']:
            # These studies intentionally retain Alice's recorded normal cap.
            assert t['gotatun_receive_buffer_bytes'] == 425984
    search = x.get('capacity_search')
    if search:
        for p in search['points']:
            ts = trials[p['first_trial_index']:p['first_trial_index']+p['trial_count']]
            assert len(ts) == p['trial_count'] == args['repetitions'] >= 3
            assert all(t['requested_payload_gbps'] == p['requested_payload_gbps'] for t in ts)
            assert all(t['receiver']['kernel_socket_drops'] == 0 for t in ts)
            assert all(abs(t['sender']['offered_payload_gbps']/p['requested_payload_gbps']-1) <= .01 for t in ts)
            worst = max(t['loss_percent'] for t in ts)
            assert math.isclose(p['max_loss_percent'], worst, abs_tol=1e-10)
            assert p['passes'] == (worst <= search['options']['loss_budget_percent'])
        if search['outcome'] == 'confirmed_bracket':
            assert search['confirmed']
            assert 0 < search['failing_upper_gbps']-search['passing_lower_gbps'] <= search['options']['resolution_gbps']+1e-9
        last = search['points'][-1] if search['points'] else {}
        assert search['confirmed'] == (last.get('phase') == 'confirmation' and last.get('passes') is True)
    reports.append({'file':path.name,'status':x['status'],'trials':len(trials),
                    'source_sha':x['source_sha'],'outcome':(search or {}).get('outcome'),
                    'confirmed':(search or {}).get('confirmed'),'error':x.get('error')})
result = {'checks':'Raw packet counts, throughput windows, offered rates, missing-block sums, actual socket sizes, per-repetition loss acceptance and confirmation decisions',
          'reports':reports,'total_completed_trials':sum(r['trials'] for r in reports)}
(root/'metadata').mkdir(exist_ok=True)
(root/'metadata'/'validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
