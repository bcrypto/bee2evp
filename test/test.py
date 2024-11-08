# *****************************************************************************
# \file test.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Python tests for openssl[bee2evp]
# \created 2019.07.10
# \version 2024.05.31
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import sys
from bash import bash_test
from belt import belt_test
from bign import bign_test
from btls import btls_test
from openssl import openssl
from util import fail, process_result

def version_test():
	retcode, out, __ = openssl('version')
	process_result('version', retcode == 0)
	print(out.decode())

def engine_test():
	retcode, out, er__ = openssl('engine -c -t bee2evp')
	process_result('engine', retcode == 0)
	print(out.decode())

if __name__ == '__main__':
	# version_test()
	# engine_test()
	# bash_test()
	# belt_test()
	bign_test()
	# btls_test()
	if fail:
		sys.exit(1)
