# *****************************************************************************
# \file server_tls.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Run BTLS server
# \created 2021.02.01
# \version 2021.02.02
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

from openssl import openssl
import threading
import signal
import os
import subprocess
import tempfile

def GenPrivateKey(privfile):
	cmd = 'genpkey -algorithm bign -pkeyopt params:bign-curve256v1 -out {}'.format(privfile)
	retcode, block, er__ = openssl(cmd)

def GenCert(privfile, certfile):
	cmd = 'req -x509 -subj "/CN=www.example.org/O=BTLS, Inc./C=BY/ST=MINSK" -new -key {} -nodes -out {}'.format(privfile, certfile)
	retcode, block, er__ = openssl(cmd)

if __name__ == '__main__':

	tmpdirname = tempfile.mkdtemp()

	priv256 = os.path.join(tmpdirname, 'priv256.key') 
	GenPrivateKey(priv256)

	cert = os.path.join(tmpdirname, 'cert.pem') 
	GenCert(priv256, cert)

	prefix = 'echo test=DHE-BIGN-WITH-BELT-DWP-HBELT |'
	cmd = 's_server -accept localhost:44330 -status_timeout 5 -timeout -key {} -cert {} -tls1_2 -engine bee2evp -cipher {}'.format(
			priv256, cert, 'DHE-BIGN-WITH-BELT-DWP-HBELT')
	openssl(cmd, prefix=prefix)

