"""Local extraction contracts: no SSH, credentials or browsers are used."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ADA = HERE.parent
HARNESS = HERE / 'harnesses/native-v1'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RelocatedSourceTests(unittest.TestCase):
    def test_version_prefers_canonical_solution_and_maps_old_paths(self):
        runner = load('entry', HERE / 'run.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            canonical = root / 'solutions/v1/src/commit'
            canonical.mkdir(parents=True)
            (root / 'catalog').mkdir()
            (root / 'catalog/locations.json').write_text(json.dumps({
                'moves': {'ADA_agent/v1': 'solutions/v1'},
                'source_roots': ['solutions'], 'identities': {}}))
            self.assertEqual(runner.resolve_source(root, 'v1'), canonical)
            self.assertEqual(runner.resolve_source(root, 'ADA_agent/v1/src/commit'), canonical)
            self.assertEqual(runner.resolve_source(root, str(root / 'ADA_agent/v1/src/commit')), canonical)

    def test_legacy_version_remains_usable_before_physical_migration(self):
        runner = load('entry', HERE / 'run.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / 'ADA_agent/v1/src/commit'
            legacy.mkdir(parents=True)
            self.assertEqual(runner.resolve_source(root, 'v1'), legacy)


class ExplicitEvidenceTests(unittest.TestCase):
    def test_plan_routes_each_vendor_to_run_evidence_and_explicit_assets(self):
        runner = load('entry', HERE / 'run.py')
        config = json.loads((HERE / 'pipeline.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source'
            source.mkdir()
            for name in runner.FILES:
                (source / name).write_text('example')
            output = Path(tmp) / 'run/evidence'
            plan = runner.make_plan(ADA, config, source, 'linux', ['gologin', 'chrome_control'], 1,
                                    output_root=output)
            for vendor, command in zip(['gologin', 'chrome_control'], plan['commands']):
                self.assertEqual(command[command.index('--output-root') + 1], str(output / vendor))
                self.assertEqual(command[command.index('--assets-directory') + 1],
                                 str(ADA / config['assets_directory']))
            self.assertFalse(output.exists())
            frozen = Path(tmp) / 'frozen-assets'
            shutil.copytree(ADA / config['assets_directory'], frozen)
            runner.make_plan(ADA, config, source, 'linux', ['gologin'], 1,
                             output_root=output, assets_directory=frozen)
            (frozen / 'index.html').write_text('wrong revision')
            with self.assertRaises(ValueError):
                runner.make_plan(ADA, config, source, 'linux', ['gologin'], 1,
                                 output_root=output, assets_directory=frozen)

    def test_explicit_frontend_assets_bind_relocated_summary(self):
        self.assertTrue((HERE / 'assess_native.py').is_file(), 'active assessor must be extracted')
        assessor = load('assessor', HERE / 'assess_native.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, assets, evidence = (root / p for p in ('source', 'frozen-assets', 'arbitrary/evidence'))
            for p in (source, assets, evidence):
                p.mkdir(parents=True)
            for name in assessor.NAMES:
                (source / name).write_text('detector')
            names = ('index.html', 'static/js/main.3256c9f3.js', 'static/js/user-agent-spoof.js', 'static/css/main.c1e9ffb3.css')
            for name in names:
                (assets / name).parent.mkdir(parents=True, exist_ok=True)
                (assets / name).write_text(name)
            digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            served = {'template_sha256': digest(assets / 'index.html'),
                      'original_template_sha256': digest(assets / 'index.html'),
                      'source_sha256': {'/static/detections/' + p.name: digest(p) for p in source.iterdir()}}
            served['source_sha256'].update({'/' + n: digest(assets / n) for n in names[1:]})
            fixtures = {'summary.json': {'rows': [], 'server_stopped': True},
                        'evaluation-plan.json': {'evaluation_request_id': 'a' * 32,
                                                 'expected_cases': [{'case_id': 'linux-gologin-headed-0'}]},
                        'stage.json': {}, 'server-manifest.json': served}
            for name, data in fixtures.items():
                (evidence / name).write_text(json.dumps(data))
            assessment = assessor.assess(source, evidence / 'summary.json', assets_directory=assets)
            self.assertTrue(assessment['served_frontend_source_bound'])
            self.assertEqual(assessment['assets_directory'], str(assets.resolve()))
            historical = root / 'historical'
            shutil.copytree(assets, historical / 'src/ada_challenge/challenge/templates')
            shutil.copytree(evidence, historical / 'experiments/run')
            self.assertTrue(assessor.assess(source, historical / 'experiments/run/summary.json')
                            ['served_frontend_source_bound'])
            (assets / names[1]).write_text('unrelated revision')
            self.assertFalse(assessor.assess(source, evidence / 'summary.json', assets_directory=assets)
                             ['served_frontend_source_bound'])


class HarnessClosureTests(unittest.TestCase):
    def test_archive_contains_staged_import_and_served_asset_closure(self):
        script = HARNESS / 'scripts/run_frontend_mode_diagnostic_matrix.py'
        self.assertTrue(script.is_file(), 'supported harness must be extracted')
        matrix = load('matrix', script)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            for name in ('ads_power', 'dolphin_anty', 'gologin', 'headless', 'multilogin', 'octo'):
                (source / (name + '.js')).write_text('detector')
            with tarfile.open(fileobj=io.BytesIO(matrix.stage_archive(source)), mode='r') as archive:
                names = set(archive.getnames())
                self.assertIn('scripts/gologin_session_support.py', names)
                self.assertIn('scripts/owned_network_trace.py', names)
                self.assertIn('scripts/owned_script_source_binding.mjs', names)
                self.assertIn('scripts/product_callsite_helper.js', names)
                self.assertIn('templates/static/js/user-agent-spoof.js', names)
                self.assertEqual(len([n for n in names if n.startswith('candidate/')]), 6)
                for name in matrix.SCRIPTS:
                    self.assertIn('scripts/' + name, names)
            assets = source / 'frozen-assets'
            shutil.copytree(HARNESS / 'src/ada_challenge/challenge/templates', assets)
            (assets / 'index.html').write_text('selected frozen frontend')
            with tarfile.open(fileobj=io.BytesIO(matrix.stage_archive(source, assets)), mode='r') as archive:
                self.assertEqual(archive.extractfile('templates/index.html').read(), b'selected frozen frontend')
            output = source / 'run/evidence/gologin'
            evidence = matrix.evidence_directory(output)
            self.assertEqual(evidence.parent, output)
            self.assertTrue(evidence.is_dir())
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)

    def test_linux_adapter_loads_configured_sdk_before_contract_check(self):
        adapter = HARNESS / 'scripts/owned_gologin_session.mjs'
        self.assertTrue(adapter.is_file(), 'Linux adapter must be extracted')
        with tempfile.TemporaryDirectory() as tmp:
            sdk = Path(tmp) / 'fake-sdk.mjs'
            sdk.write_text('console.log("SDK_OVERRIDE_LOADED"); export function GologinApi() { throw Error("must not launch"); }')
            completed = subprocess.run(['node', str(adapter)], input='{"mode":"invalid"}\n',
                env={**os.environ, 'ADA_GOLOGIN_SDK_ENTRY': str(sdk)}, capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn('SDK_OVERRIDE_LOADED', completed.stdout)
            self.assertIn('Owned profile session contract rejected', completed.stderr)


if __name__ == '__main__':
    unittest.main()
