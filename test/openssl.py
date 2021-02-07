# *****************************************************************************
# \file openssl.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over openssl commmands
# \created 2019.07.10
# \version 2021.02.07
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

import subprocess
import os
import signal
from os.path import expanduser
home = expanduser("~")

os.environ['OPENSSL_CONF'] = home + '/usr/local/openssl.cnf'
OPENSSL_EXE_PATH = home + '/usr/local/bin/openssl'

def openssl(cmd, prefix='', echo=False):
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
	return retcode^1, out, err_out
