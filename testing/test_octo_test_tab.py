"""Exercise the Mac test-tab lifecycle without opening a real browser."""
import unittest

from octo_test_tab import octo_test_tab


class FakeAppleEvents:
    def __init__(self, pid):
        self.tabs = {'personal': 'https://example.com/'}
        self.closed = []
        self.refuse_close = False

    def obj(self, kind, form, value, container=None):
        return (kind, value) if kind == 'cwin' else (kind, container, value)

    integer = text = type = enum = staticmethod(lambda value: value)

    def prop(self, name, container):
        return (name, container)

    def get(self, prop):
        return 'window-1' if prop[1][0] == 'cwin' else prop[1][-1]

    def record(self, data, kind):
        return data

    def send(self, suite, action, params):
        target = params.get('----')
        if action == 'cnte':
            return len(self.tabs)
        if action == 'crel':
            self.tabs['test'] = 'about:blank'
            return ('CrTb', ('cwin', 'window-1'), 'test')
        if action == 'setd':
            self.tabs[target[1][-1]] = params['data']
        if action == 'clos':
            self.closed.append(target[-1])
            if not self.refuse_close:
                del self.tabs[target[-1]]
        if action == 'doex':
            return bytes((target[-1] in self.tabs,))
        return None

    def returned_spec(self, value):
        return value

    def value(self, reply, key, kind):
        return reply

    def close(self):
        pass


class OctoTestTabTests(unittest.TestCase):
    url = 'http://127.0.0.1:12345/_web?order_number=0&session_id=test'

    def setUp(self):
        self.browser = FakeAppleEvents(123)
        self.row = {}

    def visit(self):
        return octo_test_tab(123, self.url, self.row, events_factory=lambda _: self.browser)

    def test_closes_owned_tab_and_preserves_preexisting_tab(self):
        with self.visit():
            self.assertEqual(self.browser.tabs['test'], self.url)
        self.assertEqual(self.browser.closed, ['test'])
        self.assertEqual(self.browser.tabs, {'personal': 'https://example.com/'})
        self.assertIs(self.row['test_tab_cleanup_confirmed'], True)

    def test_closes_tab_even_when_the_visit_raises(self):
        with self.assertRaisesRegex(ValueError, 'collector error'):
            with self.visit():
                raise ValueError('collector error')
        self.assertEqual(self.browser.closed, ['test'])
        self.assertIs(self.row['test_tab_cleanup_confirmed'], True)

    def test_failed_close_is_not_reported_as_clean(self):
        self.browser.refuse_close = True
        with self.assertRaisesRegex(RuntimeError, 'OCTO_TEST_TAB_CLEANUP_UNVERIFIED'):
            with self.visit():
                pass
        self.assertIs(self.row['test_tab_cleanup_confirmed'], False)
        self.assertIn('personal', self.browser.tabs)
