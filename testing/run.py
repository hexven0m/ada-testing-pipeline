#!/usr/bin/env python3
"""One entry point to the existing native Mac/Linux diagnostic runner.

Default: print a read-only plan. --execute explicitly launches the existing
runner, with an immutable source copy and a new local execution record.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
FILES = tuple(sorted(n + '.js' for n in ('ads_power', 'dolphin_anty', 'gologin', 'headless', 'multilogin', 'octo')))
VENDORS = ('ads_power', 'dolphin_anty', 'gologin', 'multilogin', 'octo', 'chrome_control')


def pins(source):
    return {n: hashlib.sha256((source / n).read_bytes()).hexdigest() for n in FILES
            if (source / n).is_file() and not (source / n).is_symlink()}


ASSET_FILES = ('index.html', 'static/js/main.3256c9f3.js', 'static/js/user-agent-spoof.js',
               'static/css/main.c1e9ffb3.css')


def resolve_source(root, solution):
    """Find canonical versions and relocate explicit historical workspace paths."""
    root = root.resolve()
    requested = Path(solution)
    if not requested.is_absolute() and '..' in requested.parts:
        raise ValueError('Source path cannot traverse outside the workspace.')
    if not requested.is_absolute() and len(requested.parts) == 1:
        canonical = root / 'solutions' / requested / 'src/commit'
        if canonical.is_dir():
            return canonical
        requested = Path('ADA_agent') / requested / 'src/commit'
    try:
        relative = requested.relative_to(root) if requested.is_absolute() else requested
    except ValueError:
        return requested.resolve()  # Explicit external six-file sources remain supported.
    locations = root / 'catalog/locations.json'
    if locations.is_file():
        moves = json.loads(locations.read_text()).get('moves', {})
        for old, new in sorted(moves.items(), key=lambda pair: len(Path(pair[0]).parts), reverse=True):
            try:
                suffix = relative.relative_to(old)
            except ValueError:
                continue
            relocated = Path(new) / suffix
            if relocated.is_absolute() or '..' in relocated.parts:
                raise ValueError('Relocation must remain within the ADA workspace.')
            relative = relocated
            break
    return (root / relative).resolve()


def asset_pins(directory):
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in ASSET_FILES
            if (directory / name).is_file() and not (directory / name).is_symlink()}


def make_plan(root, config, source, host, vendors, repeats, output_root=None, assets_directory=None, worker=None):
    source = source.resolve()
    if (host not in config['hosts'] or not vendors or len(set(vendors)) != len(vendors)
            or any(v not in VENDORS for v in vendors) or type(repeats) is not int or not 1 <= repeats <= 5):
        raise ValueError('Invalid host, vendor roster or repeats (1..5 required).')
    source_pins = pins(source)
    if set(source_pins) != set(FILES):
        raise ValueError('Source must contain all six regular detector files.')
    for relative, digest in config['harness_sha256'].items():
        path = root / relative
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f'Pinned harness changed/missing: {relative}; review before repinning.')
    runner = root / config['hosts'][host]['runner']
    configured_assets = root / config['assets_directory'] if config.get('assets_directory') else None
    assets = Path(assets_directory) if assets_directory is not None else configured_assets
    frontend_pins = asset_pins(configured_assets) if configured_assets is not None else None
    if assets is not None and (set(frontend_pins or {}) != set(ASSET_FILES) or asset_pins(assets) != frontend_pins):
        raise ValueError('Frozen frontend assets changed/missing; nothing launched.')
    evidence = Path(output_root) if output_root is not None else root / 'testing/runs/<run>/evidence'
    commands = [[sys.executable, str(runner), '--host', host, '--directory', str(source),
                 '--vendors', vendor, '--repeats', str(repeats), '--headless-first-call-study',
                 '--output-root', str(evidence / vendor),
                 *(['--worker', worker] if worker else []),
                 *(['--assets-directory', str(assets)] if assets is not None else [])] for vendor in vendors]
    return {'schema_version': 1, 'host': host, 'worker': worker, 'source': str(source), 'source_sha256': source_pins,
            'vendors': vendors, 'repeats': repeats, 'planned_cases': 2 * repeats * len(vendors),
            'assets_directory': str(assets) if assets is not None else None, 'assets_sha256': frontend_pins,
            'harness_sha256': dict(config['harness_sha256']),
            'commands': commands, 'scope': 'Native frontend diagnostic; separate raw first-call study; no private-gate certification.'}


def cohort_passes(result, expected):
    return (result.get('planned') == result.get('attempted') == expected
            and not result.get('missing_case_ids') and not result.get('duplicate_case_ids')
            and result.get('server_stopped') is True and result.get('served_frontend_source_bound') is True
            and all(result.get('counts', {}).get(k) == expected for k in
                    ('qualified', 'product_correct', 'payload_mode_correct', 'raw_mode_qualified', 'raw_mode_correct')))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--solution', required=True, help='Version in solutions (legacy ADA_agent fallback), or an explicit six-file source directory')
    parser.add_argument('--host', choices=('macos', 'linux'), required=True)
    parser.add_argument('--worker', help='SSH destination user@private-IPv4. Defaults to ADA_LINUX_WORKER or ADA_MACOS_WORKER.')
    parser.add_argument('--vendors', nargs='+', choices=VENDORS, required=True)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--execute', action='store_true', help='Launch native tests; default only prints the plan')
    args = parser.parse_args(argv)
    config = json.loads((ROOT / 'testing/pipeline.json').read_text())
    worker = args.worker or os.environ.get('ADA_' + args.host.upper() + '_WORKER')
    if args.execute and not worker:
        parser.error('--execute requires --worker or the corresponding ADA worker environment variable')
    source = resolve_source(ROOT, args.solution)
    plan = make_plan(ROOT, config, source, args.host, args.vendors, args.repeats, worker=worker)
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    run = ROOT / 'testing/runs' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8])
    snapshot = run / 'source'
    snapshot.mkdir(parents=True)
    for name in FILES:
        shutil.copyfile(source / name, snapshot / name)
    if pins(snapshot) != plan['source_sha256']:
        raise ValueError('Source changed during snapshot; nothing launched.')
    assets = run / 'assets'
    configured_assets = ROOT / config['assets_directory']
    for name in ASSET_FILES:
        (assets / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(configured_assets / name, assets / name)
    plan = make_plan(ROOT, config, snapshot, args.host, args.vendors, args.repeats,
                     output_root=run / 'evidence', assets_directory=assets, worker=worker)
    (run / 'PLAN.json').write_text(json.dumps(plan, indent=2) + '\n')
    (run / 'PIPELINE.json').write_text(json.dumps(config, indent=2) + '\n')
    results = {'status': 'RUNNING', 'cohorts': [], 'planned_cases': plan['planned_cases'],
               'interpretation': 'Exit codes are execution receipts, not qualification. Review runner summaries, all attempts and cleanup.'}
    output = run / 'EXECUTION.json'
    assessor_spec = importlib.util.spec_from_file_location('ada_native_assessor', ROOT / config['assessor'])
    assessor = importlib.util.module_from_spec(assessor_spec)
    assessor_spec.loader.exec_module(assessor)
    for vendor, command in zip(args.vendors, plan['commands']):
        if pins(snapshot) != plan['source_sha256']:
            raise ValueError('Frozen run source changed; no further cohorts launched.')
        make_plan(ROOT, config, snapshot, args.host, args.vendors, args.repeats,
                  output_root=run / 'evidence', assets_directory=assets, worker=worker)
        results['next_vendor'] = vendor
        output.write_text(json.dumps(results, indent=2) + '\n')
        print(f'Running {args.host} {vendor}; log: {run / (vendor + ".log")}', flush=True)
        evidence = run / 'evidence' / vendor
        before = set(evidence.glob('frontend-mode-diagnostic-*'))
        with (run / (vendor + '.log')).open('x') as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
        created = set(evidence.glob('frontend-mode-diagnostic-*')) - before
        cohort = {'vendor': vendor, 'exit_code': completed.returncode, 'command': command,
                  'status': 'UNKNOWN', 'new_evidence_directories': [str(p) for p in sorted(created)]}
        passed = False
        if len(created) == 1:
            summary = next(iter(created)) / 'summary.json'
            try:
                assessment = assessor.assess(snapshot, summary, assets_directory=assets)
                receipt = run / (vendor + '-ASSESSMENT.json')
                receipt.write_text(json.dumps(assessment, indent=2) + '\n')
                cohort['assessment'] = str(receipt)
                passed = completed.returncode == 0 and cohort_passes(assessment, 2 * args.repeats)
                cohort['status'] = 'SCOPED_PASS' if passed else 'FAIL_OR_UNKNOWN'
            except (OSError, ValueError, KeyError) as error:
                cohort['assessment_error'] = str(error)
        results['cohorts'].append(cohort)
        if not passed:
            results['status'] = 'STOPPED_REVIEW_FAILURE_OR_ACCESS_OR_CLEANUP'
            output.write_text(json.dumps(results, indent=2) + '\n')
            print(f'Stopped: inspect {output}; remaining vendors were not run.')
            return completed.returncode if completed.returncode > 0 else 2
    results['status'] = 'SELECTED_COHORTS_PASSED_FULL_SCOPE_NOT_CERTIFIED'
    output.write_text(json.dumps(results, indent=2) + '\n')
    print(f'Execution records: {run}; review native summaries before assigning PASS.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(2)
