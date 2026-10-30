#!/usr/bin/env python3
"""Owned disposable namespace fixture; never reads or edits installed STL State."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid


def run(*cmd, input=None):
    p = subprocess.run(cmd, input=input, capture_output=True, timeout=15)
    if p.returncode:
        raise RuntimeError('command_failed:' + ' '.join(cmd[:5]) + ':' + p.stderr.decode(errors='replace').strip())
    return p.stdout.decode().strip()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def identity(path):
    s = Path(path).lstat()
    return dict(dev=s.st_dev, inode=s.st_ino, mode=stat.S_IMODE(s.st_mode))


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())


def save(path, data):
    temp = path.with_suffix('.next')
    write_new(temp, (json.dumps(data, sort_keys=True, indent=2)+'\n').encode())
    os.replace(temp, path)


def namespace_identity(name):
    s = os.stat('/run/netns/' + name)
    return dict(dev=s.st_dev, inode=s.st_ino)


def read_receipt(root):
    if root.is_symlink() or identity(root)['mode'] != 0o700:
        raise RuntimeError('unsafe_fixture_root')
    data = json.loads((root/'receipt.json').read_text())
    if data['root_identity'] != identity(root):
        raise RuntimeError('fixture_root_identity_changed')
    if data['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise RuntimeError('boot_changed')
    if data.get('namespace') != namespace_identity(data['name']):
        raise RuntimeError('namespace_identity_changed')
    return data


def wg_identity(data):
    items = json.loads(run('ip', '-n', data['name'], '-d', '-j', 'link', 'show', 'dev', 'wgproof'))
    item = items[0]
    if item.get('ifalias') != data['alias'] or item['ifindex'] != data.get('ifindex') or item.get('linkinfo',{}).get('info_kind') != 'wireguard':
        raise RuntimeError('wireguard_identity_changed')
    return item


def setup(a):
    root = Path(a.root)
    key_dir = Path(a.key_dir)
    key_parent = Path('/etc/wireguard')
    if (key_parent.is_symlink() or not key_parent.is_dir() or key_parent.stat().st_uid != 0 or
            stat.S_IMODE(key_parent.stat().st_mode) & 0o022 or key_dir.parent != key_parent or
            not re.fullmatch(r'stl-u53-[a-z0-9-]{1,50}',key_dir.name)):
        raise RuntimeError('unsupported_or_unsafe_key_directory')
    if root.exists() or root.is_symlink() or key_dir.exists() or key_dir.is_symlink() or Path('/run/netns',a.name).exists():
        raise RuntimeError('fixture_collision')
    root.mkdir(mode=0o700)
    data = dict(schema=1, purpose='stl-u53-research-only', created_utc=now(), name=a.name,
                root_identity=identity(root), boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                addr=a.addr, peer=a.peer, wg_port=a.wg_port, local_port=a.local_port,
                alias='stl-u53-proof:'+str(uuid.uuid4()),key_dir=str(key_dir),stage='reserved')
    write_new(root/'receipt.json',(json.dumps(data,sort_keys=True)+'\n').encode())
    key_dir.mkdir(mode=0o700)
    data['key_dir_identity']=identity(key_dir);save(root/'receipt.json',data)
    key = run('wg','genkey').encode() + b'\n'
    write_new(key_dir/'key',key)
    data['key_identity'] = identity(key_dir/'key')
    data['public_key'] = run('wg','pubkey',input=key)
    del key
    save(root/'receipt.json',data)
    run('ip','netns','add',a.name)
    data['namespace'] = namespace_identity(a.name)
    data['stage']='namespace_created'; save(root/'receipt.json',data)
    run('ip','-n',a.name,'link','set','lo','up')
    run('ip','-n',a.name,'link','add','wgproof','type','wireguard')
    data['ifindex'] = json.loads(run('ip','-n',a.name,'-j','link','show','dev','wgproof'))[0]['ifindex']
    data['stage']='interface_created'; save(root/'receipt.json',data)
    run('ip','-n',a.name,'link','set','dev','wgproof','alias',data['alias'])
    run('ip','netns','exec',a.name,'wg','set','wgproof','private-key',str(key_dir/'key'),'listen-port',str(a.wg_port))
    run('ip','-n',a.name,'address','add',a.addr+'/32','dev','wgproof')
    run('ip','-n',a.name,'link','set','dev','wgproof','mtu','1152','up')
    run('ip','-n',a.name,'route','add',a.peer+'/32','dev','wgproof','src',a.addr)
    data['stage']='ready'; save(root/'receipt.json',data)
    wg_identity(data)
    print(json.dumps(dict(event='NAMESPACE_READY',utc=now(),**data),sort_keys=True))


def configure(a):
    root=Path(a.root);data=read_receipt(root);wg_identity(data)
    if not re.fullmatch(r'[A-Za-z0-9+/]{43}=',a.pubkey):
        raise RuntimeError('invalid_public_key')
    if data.get('peer_public_key') not in (None,a.pubkey):
        raise RuntimeError('peer_reconfiguration_requires_fresh_fixture')
    run('ip','netns','exec',data['name'],'wg','set','wgproof','peer',a.pubkey,
        'allowed-ips',data['peer']+'/32','endpoint','127.0.0.1:'+str(data['local_port']),
        'persistent-keepalive','0')
    data['peer_public_key']=a.pubkey;save(root/'receipt.json',data)
    print(json.dumps(dict(event='PEER_CONFIGURED',utc=now(),name=data['name'],public_key=data['public_key'],peer_public_key=a.pubkey,keepalive=0)))


def inspect(a):
    data=read_receipt(Path(a.root));wg_identity(data)
    fields={k:run('ip','netns','exec',data['name'],'wg','show','wgproof',k) for k in ['public-key','listen-port','peers','endpoints','allowed-ips','latest-handshakes','transfer','persistent-keepalive']}
    print(json.dumps(dict(event='INSPECT',utc=now(),name=data['name'],namespace=data['namespace'],ifindex=data['ifindex'],fields=fields),sort_keys=True))


def cleanup(a):
    root=Path(a.root);data=read_receipt(root)
    pids=run('ip','netns','pids',data['name']).strip()
    if pids:
        raise RuntimeError('namespace_processes_still_live:'+pids)
    wg_identity(data)
    key_dir=Path(data['key_dir'])
    if key_dir.parent != Path('/etc/wireguard') or identity(key_dir) != data['key_dir_identity'] or key_dir.is_symlink():
        raise RuntimeError('key_directory_identity_changed')
    if sorted(p.name for p in key_dir.iterdir()) != ['key'] or identity(key_dir/'key') != data['key_identity']:
        raise RuntimeError('private_key_identity_changed')
    run('ip','-n',data['name'],'link','del','dev','wgproof')
    if namespace_identity(data['name']) != data['namespace']:
        raise RuntimeError('namespace_changed_during_cleanup')
    run('ip','netns','del',data['name'])
    if Path('/run/netns',data['name']).exists():
        raise RuntimeError('namespace_cleanup_unconfirmed')
    (key_dir/'key').unlink();key_dir.rmdir()
    receipt=dict(event='CLEANUP',utc=now(),name=data['name'],namespace=data['namespace'],ifindex=data['ifindex'],namespace_absent=True,key_absent=True,key_dir_absent=not key_dir.exists())
    write_new(root/'cleanup.json',(json.dumps(receipt,sort_keys=True)+'\n').encode())
    print(json.dumps(receipt,sort_keys=True))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['setup','configure','inspect','cleanup'])
    p.add_argument('--root',required=True)
    p.add_argument('--name');p.add_argument('--addr');p.add_argument('--peer');p.add_argument('--pubkey');p.add_argument('--key-dir')
    p.add_argument('--wg-port',type=int,default=42511);p.add_argument('--local-port',type=int,default=42512)
    a=p.parse_args()
    if a.mode=='setup' and (not a.name or not re.fullmatch(r'u53-[a-z0-9-]{1,30}',a.name) or not a.addr or not a.peer or not a.key_dir):
        p.error('setup_arguments_required')
    if os.geteuid()!=0:
        p.error('root_required_for_disposable_netns')
    try:
        globals()[a.mode](a)
        return 0
    except Exception as exc:
        print(json.dumps(dict(event='FIXTURE_ERROR',utc=now(),mode=a.mode,error=type(exc).__name__,detail=str(exc)),sort_keys=True))
        return 2


if __name__=='__main__':
    raise SystemExit(main())
