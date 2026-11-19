"""Manage a single test tab in an already-running Mac Octo profile."""
from contextlib import contextmanager
import time


@contextmanager
def octo_test_tab(pid, url, receipt, *, events_factory=None):
    """Identify the newly created tab by ID before navigating or closing it."""
    receipt['test_tab_cleanup_confirmed'] = False
    if events_factory is None:
        from mac_apple_events import AppleEvents
        events_factory = AppleEvents
    events = events_factory(pid)
    tab = None
    try:
        front_window = events.obj('cwin', 'indx', events.integer(1))
        window_id = events.get(events.prop('ID  ', front_window))
        if not window_id:
            raise RuntimeError('OCTO_TEST_WINDOW_UNVERIFIED')
        window = events.obj('cwin', 'ID  ', events.text(window_id))

        def count_tabs():
            reply = events.send('core', 'cnte', {'----': window, 'kocl': events.type('CrTb')})
            return events.value(reply, '----', 'long')

        if (count_tabs() or 0) < 1:
            raise RuntimeError('OCTO_TEST_WINDOW_UNVERIFIED')
        # Standard Apple-event insertion location: end of this specific window.
        location = events.record({'kobj': window, 'kpos': events.enum('end ')}, 'insl')
        reply = events.send('core', 'crel', {'kocl': events.type('CrTb'), 'insh': location})
        created = events.returned_spec(reply)
        tab_id = events.get(events.prop('ID  ', created))
        if not tab_id:
            raise RuntimeError('OCTO_TEST_TAB_UNVERIFIED')
        tab = events.obj('CrTb', 'ID  ', events.text(tab_id), window)
        if events.get(events.prop('ID  ', tab)) != tab_id:
            tab = None
            raise RuntimeError('OCTO_TEST_TAB_UNVERIFIED')
        events.send('core', 'setd', {'----': events.prop('URL ', tab), 'data': events.text(url)})
        yield
    finally:
        try:
            if tab is not None:
                def exists():
                    reply = events.send('core', 'doex', {'----': tab})
                    value = events.value(reply, '----', 'bool')
                    if value not in (b'\x00', b'\x01'):
                        raise RuntimeError('OCTO_TEST_TAB_EXISTENCE_UNVERIFIED')
                    return value == b'\x01'

                if exists():
                    # Closing a window's last tab could terminate its profile.
                    if (count_tabs() or 0) < 2:
                        raise RuntimeError('OCTO_TEST_TAB_IS_LAST_WINDOW_TAB')
                    events.send('core', 'clos', {'----': tab})
                    deadline = time.monotonic() + 2
                    while exists():
                        if time.monotonic() >= deadline:
                            raise RuntimeError('OCTO_TEST_TAB_CLEANUP_UNVERIFIED')
                        time.sleep(0.05)
                receipt['test_tab_cleanup_confirmed'] = True
        finally:
            events.close()
