# *****************************************************************************
# \file belt.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over belt commmands
# \created 2019.12.09
# \version 2020.01.29
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

from openssl import openssl
from settings import *

def beltBlockEncr(block, key):
	assert len(block) * 8 == 128

	plain = b64_encoder(block)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -e -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block


def beltBlockDecr(block, key):
	assert len(block) * 8 == 128

	plain = b64_encoder(block)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block

def beltECBEncr(src, key):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltECBDecr(src, key):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest	

def beltCBCEncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCBCDecr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCFBEncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCFBDecr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCTREncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCTRDecr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltMAC(src, key):
	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key)*4
	
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{}'.format(256, key)
	retcode, out, er__ = openssl(cmd, prefix, True)
	mac = out.split(' ')[1][:-1]
	return bytes(hex_decoder(mac)[0])
	
def beltHash(src):
	plain = b64_encoder(src)[0].encode()

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -belt-hash'.format()
	retcode, out, er__ = openssl(cmd, prefix, True)
	hash_ = out.split(' ')[1][:-1]
	return bytes(hex_decoder(hash_)[0])



