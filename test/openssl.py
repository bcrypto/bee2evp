# *****************************************************************************
# \file openssl.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over openssl commmands
# \created 2019.07.10
# \version 2019.07.19
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

import subprocess
import os

os.environ['OPENSSL_CONF'] = '/usr/local/openssl.cnf'
OPENSSL_EXE_PATH = '/usr/local/bin/openssl'

def openssl(cmd, prefix='', echo = False):
	if echo:
		print(prefix + ' ' + cmd)
	p = subprocess.Popen(prefix + ' ' + OPENSSL_EXE_PATH + ' ' + cmd,
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE,
					stdin=subprocess.PIPE,
					shell=True)

	out, err_out = p.communicate()
	retcode = p.poll()
	return retcode, out, err_out
