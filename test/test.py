# *****************************************************************************
# \file test.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Python tests for openssl[bee2evp]
# \created 2019.07.10
# \version 2019.07.16
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

from openssl import openssl

def test_version():
    assert openssl('version') == 0

def test_engine():
	assert openssl('engine -c -t bee2evp') == 0

if __name__ == '__main__':
    test_version()
    test_engine()
