"""Summarize exact-source local diagnostics; never private acceptance."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re

PRODUCTS = ('ads_power', 'dolphin_anty', 'gologin', 'multilogin', 'octo')
NAMES = {p + '.js' for p in (*PRODUCTS, 'headless')}


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def assess(directory, summary_path, assets_directory=None):
    pins = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.glob('*.js')}
    if set(pins) != NAMES:
        raise ValueError('exact six-file candidate required')
    summary = json.loads(summary_path.read_text())
    plan = json.loads(summary_path.with_name('evaluation-plan.json').read_text())
    stage = json.loads(summary_path.with_name('stage.json').read_text())
    served = json.loads(summary_path.with_name('server-manifest.json').read_text())
    served_pins = served.get('source_sha256') or {}
    # Historical callers retain their frozen runtime-relative asset lookup.
    # New callers pass the run's immutable asset snapshot explicitly.
    templates = (Path(assets_directory) if assets_directory is not None else
                 summary_path.parents[2] / 'src/ada_challenge/challenge/templates')
    template_digest = hashlib.sha256((templates / 'index.html').read_bytes()).hexdigest()
    frontend_bound = (served.get('template_sha256') == template_digest and
                      served.get('original_template_sha256') == template_digest and
                      all(served_pins.get('/static/detections/' + name) == digest
                          for name, digest in pins.items()) and
                      all(served_pins.get('/' + name) == hashlib.sha256(
                          (templates / name).read_bytes()).hexdigest()
                          for name in ('static/js/main.3256c9f3.js',
                                       'static/js/user-agent-spoof.js',
                                       'static/css/main.c1e9ffb3.css')))
    planned = plan['expected_cases']
    if not isinstance(planned, list) or not planned:
        raise ValueError('nonempty frozen evaluation plan required')
    expected_cases = {case['case_id']: case for case in planned}
    if len(expected_cases) != len(planned):
        raise ValueError('duplicate frozen plan case IDs')
    request_id = plan.get('evaluation_request_id')
    if not isinstance(request_id, str) or not re.fullmatch('[a-f0-9]{32}', request_id):
        raise ValueError('valid frozen evaluation request ID required')
    case_counts = Counter(row.get('case_id') for row in summary.get('rows', []))
    rows = []
    for row in summary.get('rows', []):
        frontend = row.get('frontend') or row.get('frontend_observation') or {}
        audit = row.get('native_launch_audit') or {}
        mode = row.get('mode')
        raw = frontend.get('headless_first_call_study') or {}
        expected_case = expected_cases.get(row.get('case_id'), {})
        source = (row.get('expected_detector_sha256') == pins and
                  frontend.get('detector_sha256') == pins and
                  stage.get('candidate_sha256') == pins and
                  plan.get('source_sha256') == pins and frontend_bound)
        types = frontend.get('raw_product_types') or {}
        verdicts = frontend.get('raw_product_verdicts') or {}
        duration = frontend.get('duration_ms')
        budget = frontend.get('observer_budget_ms')
        qualified = bool(source and row.get('state') == 'delivered' and
                         case_counts[row.get('case_id')] == 1 and
                         row.get('evaluation_request_id') == request_id and
                         row.get('cleanup_confirmed') is True and
                         frontend.get('state') == 'collector-confirmed' and
                         frontend.get('observer_evidence_version') == 2 and
                         frontend.get('completed_within_observer_budget') is True and
                         finite_number(duration) and finite_number(budget) and
                         0 <= duration <= budget <= 45000 and
                         frontend.get('detector_errors') == [] and
                         type(frontend.get('order_number')) is int and
                         frontend.get('order_number') == row.get('order_number') and
                         type(frontend.get('http_status')) is int and
                         200 <= frontend.get('http_status') < 300 and
                         frontend.get('session_binding_verified') is True and
                         frontend.get('collector_response_complete') is True and
                         frontend.get('raw_product_payload_consistent') is True and
                         all(types.get(p) == 'boolean' and type(verdicts.get(p)) is bool
                             for p in PRODUCTS) and
                         audit.get('state') == 'verified' and
                         audit.get('headless_flag') is (mode == 'headless') and
                         expected_case.get('product') == row.get('vendor') and
                         expected_case.get('host_os') == row.get('host_os') and
                         expected_case.get('mode') == mode and
                         expected_case.get('order_number') == row.get('order_number') and
                         expected_case.get('repeat') == row.get('repeat'))
        expected = [] if row.get('vendor') == 'chrome_control' else [row.get('vendor')]
        product_ok = (frontend.get('submitted_framework') == expected and
                      all(verdicts.get(p) is (p in expected) for p in PRODUCTS))
        mode_ok = frontend.get('headless') is (mode == 'headless')
        raw_qualified = bool(qualified and raw.get('state') == 'BOOLEAN' and
                             type(raw.get('value')) is bool and
                             raw.get('source_bound') is True and
                             raw.get('preload_source_bound') is True and
                             raw.get('preload_sha256') == served_pins.get(
                                 '/static/js/user-agent-spoof.js') and
                             raw.get('detector_sha256') == pins['headless.js'] and
                             raw.get('url_restored') is True and
                             raw.get('history_unchanged') is True and
                             raw.get('frame_count_restored') is True and
                             raw.get('frontend_unchanged') is True)
        raw_qualified = bool(raw_qualified and
                             raw.get('observation') == 'first-call-separate-document' and
                             raw.get('diagnostic_only') is True and
                             raw.get('original_call_intercepted') is False and
                             raw.get('page') == 'dedicated-raw-mode-document' and
                             finite_number(raw.get('duration_ms')) and
                             0 <= raw['duration_ms'] < 30000)
        rows.append({
            'case_id': row.get('case_id'), 'host': row.get('host_os'),
            'vendor': row.get('vendor'), 'mode': mode, 'repeat': row.get('repeat'),
            'state': row.get('state'), 'source_bound': source, 'qualified': qualified,
            'cleanup_confirmed': row.get('cleanup_confirmed'),
            'submitted_framework': frontend.get('submitted_framework'),
            'product_correct': product_ok if qualified else None,
            'payload_mode_correct': mode_ok if qualified else None,
            'raw_mode_qualified': raw_qualified,
            'raw_mode_correct': (raw.get('value') is (mode == 'headless')) if raw_qualified else None,
            'detector_errors': frontend.get('detector_errors'),
            'failure': row.get('failure'),
        })
    return {
        'summary': str(summary_path.resolve()), 'source_sha256': pins,
        'assets_directory': str(templates.resolve()),
        'assets_sha256': {name: hashlib.sha256((templates / name).read_bytes()).hexdigest()
                          for name in ('index.html', 'static/js/main.3256c9f3.js',
                                       'static/js/user-agent-spoof.js', 'static/css/main.c1e9ffb3.css')},
        'diagnostic_only': True, 'private_acceptance': 'UNCONFIRMED',
        'original_headless_call': 'frontend payload; original raw return not intercepted',
        'raw_mode_scope': 'separate first call in a dedicated source/preload-bound document',
        'server_stopped': summary.get('server_stopped'),
        'served_frontend_source_bound': frontend_bound,
        'duplicate_case_ids': sorted(k for k, v in case_counts.items() if v > 1),
        'planned': len(planned), 'attempted': len(rows),
        'missing_case_ids': sorted({r['case_id'] for r in planned} - {r['case_id'] for r in rows}),
        'counts': dict(Counter({
            'qualified': sum(r['qualified'] for r in rows),
            'product_correct': sum(r['product_correct'] is True for r in rows),
            'product_wrong': sum(r['product_correct'] is False for r in rows),
            'payload_mode_correct': sum(r['payload_mode_correct'] is True for r in rows),
            'payload_mode_wrong': sum(r['payload_mode_correct'] is False for r in rows),
            'raw_mode_qualified': sum(r['raw_mode_qualified'] for r in rows),
            'raw_mode_correct': sum(r['raw_mode_correct'] is True for r in rows),
            'raw_mode_wrong': sum(r['raw_mode_correct'] is False for r in rows),
            'unqualified': sum(not r['qualified'] for r in rows),
        })), 'rows': rows,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('summary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--assets-directory', type=Path,
                        help='Frozen frontend assets; omitted only for historical runtime-relative reports.')
    args = parser.parse_args()
    result = assess(args.directory, args.summary, assets_directory=args.assets_directory)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('planned', 'attempted', 'counts', 'missing_case_ids')}))
