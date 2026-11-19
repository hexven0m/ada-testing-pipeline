import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('ada_testing', Path(__file__).with_name('run.py'))
module = importlib.util.module_from_spec(SPEC)
if Path(SPEC.origin).exists():
    SPEC.loader.exec_module(module)


class RunnerPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'ADA_agent/example/src/commit'
        self.source.mkdir(parents=True)
        for name in ('ads_power', 'dolphin_anty', 'gologin', 'headless', 'multilogin', 'octo'):
            (self.source / (name + '.js')).write_text('example')
        self.runner = self.root / 'research/runtime/scripts/run_frontend_mode_diagnostic_matrix.py'
        self.runner.parent.mkdir(parents=True)
        self.runner.write_text('raise RuntimeError("must never execute during planning")')
        self.config = {'hosts': {'linux': {'runner': self.runner.relative_to(self.root).as_posix()}},
                       'harness_sha256': {}}
        import hashlib
        self.config['harness_sha256'][self.runner.relative_to(self.root).as_posix()] = hashlib.sha256(self.runner.read_bytes()).hexdigest()

    def test_plan_is_read_only_and_preserves_vendor_roster(self):
        before = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*'))
        plan = module.make_plan(self.root, self.config, self.source, 'linux', ['ads_power', 'chrome_control'], 2)
        self.assertEqual(plan['planned_cases'], 8)
        self.assertEqual(len(plan['commands']), 2)
        self.assertEqual(before, sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*')))

    def test_modified_harness_refuses_before_launch(self):
        self.runner.write_text('modified')
        with self.assertRaises(ValueError):
            module.make_plan(self.root, self.config, self.source, 'linux', ['ads_power'], 2)

    def test_partial_source_and_invalid_vendors_refuse(self):
        with self.assertRaises(ValueError):
            module.make_plan(self.root, self.config, self.source, 'linux', ['unknown'], 2)
        (self.source / 'octo.js').unlink()
        with self.assertRaises(ValueError):
            module.make_plan(self.root, self.config, self.source, 'linux', ['ads_power'], 2)

    def test_execution_success_does_not_override_missing_or_wrong_observations(self):
        result = {'planned': 4, 'attempted': 4, 'missing_case_ids': [], 'duplicate_case_ids': [],
                  'server_stopped': True, 'served_frontend_source_bound': True,
                  'counts': {k: 4 for k in ('qualified', 'product_correct', 'payload_mode_correct',
                                           'raw_mode_qualified', 'raw_mode_correct')}}
        self.assertTrue(module.cohort_passes(result, 4))
        result['counts']['raw_mode_correct'] = 3
        self.assertFalse(module.cohort_passes(result, 4))
        result['counts']['raw_mode_correct'] = 4
        result['missing_case_ids'] = ['missing']
        self.assertFalse(module.cohort_passes(result, 4))


if __name__ == '__main__':
    unittest.main()
