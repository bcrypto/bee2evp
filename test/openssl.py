# *****************************************************************************
# \file openssl.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over openssl commmands
# \created 2019.07.10
# \version 2024.05.31
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import subprocess
import os

os.environ['OPENSSL_CONF'] = './openssl.cnf'
OPENSSL_EXE_PATH = './bin/openssl'

def openssl(cmd, prefix='', echo=False, check=True):
	cmd = '{} {} {}'.format(prefix, OPENSSL_EXE_PATH, cmd)
	if echo:
		print(cmd)

	p = subprocess.Popen(cmd,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		stdin=subprocess.PIPE,
		shell=True)

	out, err_out = p.communicate()
	retcode = p.poll()
	if retcode and check:
		raise CalledProcessError(retcode, p.args, output=stdout, stderr=stderr)

	return retcode ^ 1, out, err_out

def openssl2(cmd, prefix='', echo=False):
	cmd = '{} {} {}'.format(prefix, OPENSSL_EXE_PATH, cmd)
	if echo:
		print(cmd)
	p = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
	return p
