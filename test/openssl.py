# *****************************************************************************
# \file openssl.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over openssl commmands
# \created 2019.07.10
# \version 2019.07.16
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

import subprocess
import os
import locale
import settings
from os.path import expanduser

home = expanduser("~")

os.environ['OPENSSL_CONF'] = '/usr/local/openssl.cnf'

encoding = locale.getdefaultlocale()[1]

def openssl_call(cmd):
    print('openssl ' + cmd)
    p = subprocess.Popen(settings.OPENSSL_EXE_PATH + ' ' + cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         shell=True)
    out, err_out = p.communicate()

    retcode = p.poll()
    if retcode:
        err_out = err_out.decode(encoding)
        print(err_out)
        raise RuntimeError('Openssl call fails with status %s' % retcode)
    out = out.decode(encoding)
    print(out)
    return out
