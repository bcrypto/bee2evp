# *****************************************************************************
# \file bign.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over bign methods
# \created 2019.12.09
# \version 2020.02.17
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************
from openssl import openssl
from settings import *

def bignStdParams(name, out_filename, specified=False, cofactor=False):
	options = '-pkeyopt params:{}'.format(name)
	if specified:
		options += ' -pkeyopt enc_params:specified'

	if cofactor:
		options += ' -pkeyopt enc_params:cofactor'

	cmd = 'genpkey -genparam -algorithm bign {} -out {}'.format(options, out_filename)
	retcode, out, er__ = openssl(cmd)
	return out

def bignGenKeypair(params_file, out_filename):
	cmd = 'genpkey -paramfile {} -out {}'.format(params_file, out_filename)
	retcode, out, er__ = openssl(cmd)
	return out

def bignCalcPubkey(private_key_file, out_filename):
	cmd = 'pkey -in {} -pubout -out {}'.format(private_key_file, out_filename)
	retcode, public_key, er__ = openssl(cmd)
	return public_key

def bignSign(prkey, hashname, src , dest):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -{} -sign {} -out {}'.format(hashname, prkey, dest)
	retcode, out, er__ = openssl(cmd, prefix=prefix, echo=False)
	return retcode

def bignSign2(prkey, hashname, src, dest):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -{} -sign {} -sigopt sig:deterministic -out {}'.format(hashname, prkey, dest)
	retcode, out, er__ = openssl(cmd, prefix=prefix, echo=False)
	return retcode

def bignVerify(prkey, hashname, src, sign_file):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -{} -prverify {} -hex -signature {}'.format(hashname, prkey, sign_file)
	retcode, out, er__ = openssl(cmd, prefix=prefix, echo=False)
	return out.decode()[:-1]

'''def bignStdParams(name, specified=False, cofactor=False):
	options = '-pkeyopt params:{}'.format(name)
	if specified:
		options += ' -pkeyopt enc_params:specified'

	if cofactor:
		options += ' -pkeyopt enc_params:cofactor'

	cmd = 'genpkey -genparam -algorithm bign {}'.format(options)
	retcode, out, er__ = openssl(cmd)
	return out'''
	
'''def bignGenKeypair(name, specified=False, cofactor=False):
	options = '-pkeyopt params:{}'.format(name)
	if specified:
		options += ' -pkeyopt enc_params:specified'

	if cofactor:
		options += ' -pkeyopt enc_params:cofactor'

	cmd = 'genpkey -algorithm bign {}'.format(options)
	retcode, out, er__ = openssl(cmd)
	return out'''

'''def bignCalcPubkey(private_key):
	private_key = b64_encoder(private_key)[0].decode()
	private_key = private_key.replace('\n','')
	prefix = 'echo ' + private_key + ' | python -m base64 -d | '
	cmd = 'pkey -pubout'
	retcode, public_key, er__ = openssl(cmd, prefix, False)
	return public_key'''

'''def bignSign(private_key):
	private_key = b64_encoder(private_key)[0].decode()
	private_key = private_key.replace('\n','')
	
	prefix = 'privkey=$(echo {} | python -m base64 -d); /dev/fd/0>$privkey; echo 123;'.format(private_key)
	cmd = 'dgst -d -hex -keyform PEM -sign /dev/fd/0 test.py'
	#cmd = "dgst -sign {} -hex".format("<(echo "+ private_key + "  | python -m base64 -d)")
	retcode, sign, er__ = openssl(cmd, prefix=prefix,echo=True)
	print(er__.decode())
	return sign'''