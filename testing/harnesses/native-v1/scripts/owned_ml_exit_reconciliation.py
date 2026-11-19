"""Require recorded native exit before reconciling an owned one-time ML journal.

No API retry, stop, kill, profile mutation, token or identity export. A missing
acknowledgement stays UNKNOWN even when actual native cleanup is proven.
"""
import hashlib,json,os,re,stat
from pathlib import Path

def reconcile_owned_ml_exit(journal,root,profiles,expected_headless,*,pid_exists=None):
 try:
  if type(expected_headless) is not bool or journal.name!='private-owner.json' or journal.is_symlink():return None
  if journal.parent.is_symlink() or not re.fullmatch(r'task-[0-9]+',journal.parent.name):return None
  if journal.resolve().parent.parent!=(root/'artifacts').resolve():return None
  info=journal.stat()
  if info.st_uid!=os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)&0o077:return None
  raw=journal.read_bytes();record=json.loads(raw)
  if record.get('vendor')!='multilogin' or not isinstance(record.get('owned_created_id'),str) or not record['owned_created_id'] or record.get('owned_reused_id'):return None
  if record.get('expected_headless') is not expected_headless:return None
  pids=record.get('listener_owner_pids');port=record.get('owned_debug_port')
  if not isinstance(pids,list) or not pids or any(type(pid) is not int or pid<=1 for pid in pids):return None
  if type(port) is not int or not 1024<=port<=65535:return None
  exists=pid_exists or (lambda pid:Path('/proc',str(pid)).exists())
  if not all(exists(pid) is False for pid in pids):return None
  if profiles.socket_owners(port) or profiles.owned_listener_refused(port) is not True:return None
  archive=journal.with_name('private-owner.reconciled-native-exit.json')
  if archive.exists() or archive.is_symlink():return None
  os.rename(journal,archive)
  if archive.read_bytes()!=raw:raise OSError('owned journal preservation failed')
  return {'cleanup_confirmed':True,'method':'recorded-one-time-native-exit','recorded_native_pids_exited':True,'owned_debug_socket_absent':True,'owned_listener_definitively_refused':True,'journal_exact_bytes_preserved':True,'journal_sha256':hashlib.sha256(raw).hexdigest(),'api_stop_acknowledgement':'UNKNOWN','profile_mutations':[],'api_stop_retried':False}
 except (OSError,ValueError,TypeError,KeyError,profiles.ProfileError):return None
