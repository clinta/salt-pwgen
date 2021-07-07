# -*- coding: utf-8 -*-
'''
Module for getting and generating random passwords for storage in a pass db.
'''

# Import python libs
import logging

import salt.utils
import os
import subprocess
import re
import hashlib
import crypt
import base64
import yaml
import time


log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only work on POSIX-like systems
    '''
    # Disable on Windows, a specific file module exists:
    if salt.utils.platform.is_windows():
        return False

    return True


def get_pw(pw_name, pw_store, pw_meta_dir, pw_max_age=-1):
    '''
    Get a password, or generate one if it doesn't exist
    '''
    ansi_escape = re.compile(r'\x1b[^m]*m')
    pass_env = os.environ.copy()
    pass_env['PASSWORD_STORE_DIR'] = pw_store
    pw_file = '{0}/{1}.gpg'.format(pw_store, pw_name)
    meta_file = '{0}/{1}/{2}.meta'.format(pw_meta_dir, pw_store, pw_name)
    subprocess.call(['pass', 'git', 'pull'], env=pass_env)
    pw_file_hash = 'default_file_hash'
    pw_expire = False

    if os.path.isfile(pw_file):
        with open(pw_file, 'r') as f:
            pw_file_hash = hashlib.sha256(f.read()).hexdigest()

    pw_meta = {'pw_file_sha256': 'default_meta_hash'}
    if os.path.isfile(meta_file):
        with open(meta_file, 'r') as f:
            pw_meta = yaml.safe_load(f)

    if pw_max_age > -1 and os.path.isfile(pw_file) and os.path.isfile(meta_file):
        pw_expire_thresh = time.time() - pw_max_age * 86400
        file_times = [ os.path.getmtime(i) for i in (pw_file, meta_file) ]
        if not all(i > pw_expire_thresh for i in file_times):
            pw_expire = True

    if not isinstance(pw_meta, dict) or 'pw_file_sha256' not in pw_meta:
        pw_meta = {'pw_file_sha256': 'default_meta_hash'}

    print(pw_meta)
    print(pw_file_hash)
    if pw_meta['pw_file_sha256'] != pw_file_hash or pw_expire:
        pass_output = subprocess.check_output(['pass', 'generate', '-n', '-f', pw_name, '16'], env=pass_env)
        subprocess.call(['pass', 'git', 'push'], env=pass_env)
        pass_plaintext = ansi_escape.sub('', pass_output).strip().split('\n')[-1]
        pw_meta['pw_hash'] = crypt.crypt(pass_plaintext, '$6${0}$'.format(base64.b64encode(os.urandom(16))[:16]))

        with open(pw_file, 'r') as f:
            pw_file_hash = hashlib.sha256(f.read()).hexdigest()
        pw_meta['pw_file_sha256'] = pw_file_hash

        if not os.path.exists(os.path.dirname(meta_file)):
            os.makedirs(os.path.dirname(meta_file))

        with open(meta_file, 'w') as f:
            f.write(yaml.safe_dump(pw_meta, default_flow_style=False))

    return pw_meta['pw_hash']
