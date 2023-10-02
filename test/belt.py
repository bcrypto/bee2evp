# *****************************************************************************
# \file belt.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over STB 34.101.31 (belt) algorithms
# \created 2019.12.09
# \version 2023.10.02
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

from openssl import openssl
from settings import hex_encoder, b64_encoder, hex_decoder, b64_decoder

def beltBlockEncr(block, key):
	assert len(block) == 16

	plain = b64_encoder(block)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -e -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix)
	return block


def beltBlockDecr(block, key):
	assert len(block) == 16

	plain = b64_encoder(block)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix)
	return block

def beltECBEncr(src, key):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltECBDecr(src, key):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest	

def beltCBCEncr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(
		key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCBCDecr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(
		key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCFBEncr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(
		key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCFBDecr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(
	key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCTREncr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(
	key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCTRDecr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(
		key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltMAC(src, key):
	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)
	
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{}'.format(key_bitlen, key)
	retcode, out, er__ = openssl(cmd, prefix)
	mac = out.decode().split(' ')[1][:-1]
	mac = mac.strip()
	return bytes(hex_decoder(mac)[0])

def beltHMAC(src, key):
	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)
	
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -mac belt-hmac -macopt hexkey:{}'.format(key)
	retcode, out, er__ = openssl(cmd, prefix)
	mac = out.decode().split(' ')[1][:-1]
	mac = mac.strip()
	return bytes(hex_decoder(mac)[0])

def beltHash(src):
	plain = b64_encoder(src)[0].decode()

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -belt-hash'.format()
	retcode, out, er__ = openssl(cmd, prefix)
	hash_ = out.decode().split(' ')[1][:-1]
	hash_ = hash_.strip()
	return bytes(hex_decoder(hash_)[0])
