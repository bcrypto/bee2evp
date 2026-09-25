# *****************************************************************************
# \file openssl.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over openssl commmands
# \created 2019.07.10
# \version 2024.05.31
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import os, subprocess

OPENSSL_EXE_PATH = 'openssl'

# bee2evp attached as a provider: no -engine option (removed in OpenSSL 4)
PROVIDER = os.environ.get('BEE2EVP_PROVIDER') == '1'

def adjust(cmd):
	return cmd.replace('-engine bee2evp ', '') if PROVIDER else cmd

def openssl(cmd, prefix='', echo=False, check=True):
	cmd = '{} {} {}'.format(prefix, OPENSSL_EXE_PATH, adjust(cmd))
	if echo:
		print(cmd)

	p = subprocess.Popen(cmd,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		stdin=subprocess.PIPE,
		shell=True)

	out, err_out = p.communicate()
	retcode = p.poll()
	if retcode != 0 and check:
		raise subprocess.CalledProcessError(retcode, p.args)

	return retcode, out, err_out

def openssl2(cmd, prefix='', echo=False):
	cmd = '{} {} {}'.format(prefix, OPENSSL_EXE_PATH, adjust(cmd))
	if echo:
		print(cmd)
	p = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
	return p
