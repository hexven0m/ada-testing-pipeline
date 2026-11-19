"""Check that the standalone export routes only to explicit private workers."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from run import FILES, ROOT, make_plan
from test_restructure import HARNESS, load

matrix = load('matrix_for_worker_tests', HARNESS / 'scripts/run_frontend_mode_diagnostic_matrix.py')


class WorkerTests(unittest.TestCase):
    def test_mac_plan_routes_to_the_selected_worker(self):
        config = json.loads((ROOT / 'testing/pipeline.json').read_text())
        with TemporaryDirectory() as folder:
            source = Path(folder)
            for name in FILES:
                (source / name).write_text('fixture')
            plan = make_plan(ROOT, config, source, 'macos', ['multilogin'], 1,
                             worker='operator@100.64.0.42')
            command = plan['commands'][0]
            self.assertEqual(command[command.index('--worker') + 1], 'operator@100.64.0.42')
            self.assertEqual(plan['worker'], 'operator@100.64.0.42')

    def test_multilogin_uses_the_selected_private_address(self):
        for host in ('linux', 'macos'):
            destination, _ = matrix.ssh_connection(host, 'operator@100.64.0.42')
            self.assertEqual(destination, 'operator@100.64.0.42')
            transport = matrix.diagnostic_transport(['multilogin'], host, private_address='100.64.0.42')
            self.assertEqual(transport['bind_host'], '100.64.0.42')

    def test_dispatch_rejects_missing_and_public_worker(self):
        for worker in (None, 'operator@8.8.8.8', '-option@100.64.0.42'):
            with self.assertRaises(ValueError):
                matrix.ssh_connection('linux', worker)
