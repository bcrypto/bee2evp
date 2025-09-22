# *****************************************************************************
# \file test.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Python tests for openssl[bee2evp]
# \created 2019.07.10
# \version 2024.05.31
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

from bash import bash_test
from belt import belt_test
from bign import bign_test
from btls import btls_test
from openssl import openssl
from util import fail, process_result

import re
import sys

def version_test():
	retcode, out, __ = openssl('version')
	openssl_version_string = out.decode()
	match = re.search(r"OpenSSL (\d+)\.", openssl_version_string)
	process_result('version', retcode == 0 and match)
	print(out.decode())
	openssl_version_major = match.group(1)
	return openssl_version_major


def engine_test():
	retcode, out, er__ = openssl('engine -c -t bee2evp')
	process_result('engine', retcode == 0)
	print(out.decode())

if __name__ == '__main__':
	openssl_version_major = int(version_test())
	engine_test()
	bash_test()
	belt_test()
	bign_test()
	btls_test(openssl_version_major)
	if fail:
		sys.exit(1)
