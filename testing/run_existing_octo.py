#!/usr/bin/env python3
"""Run two headed visits on each of three approved, already-running Mac Octo profiles."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
from uuid import UUID, uuid4

from run import ASSET_FILES, FILES, ROOT, make_plan, resolve_source


def approved_profiles(path):
    profiles = json.loads(path.read_text())
    if (not isinstance(profiles, list) or len(profiles) != 3
            or any(not isinstance(value, str) or UUID(value).hex != value for value in profiles)
            or len(set(profiles)) != 3):
        raise ValueError('Expected three distinct lowercase, dashless Octo UUIDs')
    return profiles


def stage_contents(config, source, plan, approved):
    collector = ROOT / config['hosts']['macos']['runner']
    assets = ROOT / config['assets_directory']
    contents = {}
    for prefix, root, names, hashes in (
            ('candidate', source, FILES, plan['source_sha256']),
            ('templates', assets, ASSET_FILES, plan['assets_sha256'])):
        for name in names:
            data = (root / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != hashes[name]:
                raise ValueError('Source or frontend changed during staging')
            contents[f'{prefix}/{name}'] = data
    contents.update({
        'source-pins.json': json.dumps(plan['source_sha256']).encode(),
        'approved-private.json': json.dumps(approved).encode(),
        'manual_octo_worker.py': (ROOT / 'testing/octo_existing_worker.py').read_bytes(),
        'octo_test_tab.py': (ROOT / 'testing/octo_test_tab.py').read_bytes(),
        'mac_apple_events.py': (ROOT / 'testing/mac_apple_events.py').read_bytes(),
        'serve_frontend_mode_diagnostic.py': collector.with_name('serve_frontend_mode_diagnostic.py').read_bytes(),
    })
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as archive:
        for name, value in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(value))
    return data.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--solution', required=True)
    parser.add_argument('--worker', default=os.environ.get('ADA_MACOS_WORKER'))
    parser.add_argument('--approved-profiles', type=Path, required=True,
                        help='Local JSON file containing the three approved profile IDs.')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    profiles = approved_profiles(args.approved_profiles)
    config = json.loads((ROOT / 'testing/pipeline.json').read_text())
    source = resolve_source(ROOT, args.solution)
    plan = make_plan(ROOT, config, source, 'macos', ['octo'], 2)
    plan.pop('commands')  # The normal disposable launcher is a separate route.
    plan.update(worker=args.worker, planned_cases=6, scope='Existing Mac Octo profiles, headed payloads only')
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    if not args.worker or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*@[A-Za-z0-9.][A-Za-z0-9.-]*', args.worker):
        parser.error('Specify --worker user@host or ADA_MACOS_WORKER')

    def ssh(command, **kwargs):
        return subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                               args.worker, shlex.join(command)], **kwargs)

    data = stage_contents(config, source, plan, profiles)
    platform = ssh(['uname', '-s'], capture_output=True, check=True, timeout=20).stdout.strip()
    if platform != b'Darwin':
        raise ValueError('The existing-profile worker must be a Mac')
    stage = ssh(['mktemp', '-d', '/tmp/ada-existing-octo-XXXXXXXX'], capture_output=True,
                check=True, timeout=20).stdout.decode().strip()
    if not re.fullmatch(r'/tmp/ada-existing-octo-[A-Za-z0-9]{8}', stage):
        raise ValueError('Unexpected worker stage path')
    out = ROOT / 'testing/runs' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') +
                                  '-octo-' + uuid4().hex[:8])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.mkdir(mode=0o700)
    (out / 'PLAN.json').write_text(json.dumps(plan, indent=2) + '\n')
    ssh(['tar', '-xzf', '-', '-C', stage], input=data, check=True, timeout=30)
    with (out / 'octo.log').open('x') as log:
        result = ssh(['python3', stage + '/manual_octo_worker.py'], stdout=log, stderr=subprocess.STDOUT)
    report = ssh(['cat', stage + '/manual-results.json'], capture_output=True, timeout=20)
    manifest = ssh(['cat', stage + '/server/manifest.json'], capture_output=True, timeout=20)
    if not manifest.returncode:
        (out / 'server-manifest.json').write_bytes(manifest.stdout)
    print(f'Octo evidence: {out}', flush=True)
    if report.returncode:
        return 2
    (out / 'manual-results.json').write_bytes(report.stdout)
    observed = json.loads(report.stdout)
    rows = observed['rows']
    passed = (result.returncode == 0 and observed.get('server_stopped') is True
              and observed.get('source_sha256') == plan['source_sha256']
              and observed.get('test_tab_cleanup_confirmed') is True and len(rows) == 6
              and all(all(row.get(key) is True for key in
                          ('product_correct', 'mode_correct', 'profile_still_headed_and_bound',
                           'test_tab_cleanup_confirmed')) for row in rows))
    print('SCOPED_HEADED_PAYLOAD_PASS' if passed else 'FAIL_OR_INCOMPLETE')
    return 0 if passed else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'Octo run failed: {type(error).__name__}', file=sys.stderr)
        raise SystemExit(2)
