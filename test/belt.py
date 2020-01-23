from openssl import openssl
import codecs

ECHO_EXE_PATH = '/bin/echo'

hex_encoder = codecs.getencoder('hex')
b64_encoder = codecs.getencoder('base64')
hex_decoder = codecs.getdecoder('hex')
b64_decoder = codecs.getdecoder('base64')

def beltBlockEncr(block, key):
	assert len(block) * 8 == 128

	plain = b64_encoder(block)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -e -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block


def beltBlockDecr(block, key):
	assert len(block) * 8 == 128

	plain = b64_encoder(block)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block

def beltECBEncr(src, key):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltECBDecr(src, key):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest	

def beltCBCEncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCBCDecr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCFBEncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCFBDecr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCTREncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCTRDecr(right_plain_msg, right_enc_msg, key, msg_len, iv):
	assert (len(src) * 8) % 128 == 0

	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	iv = hex_encoder(iv)[0].encode()
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -d -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltMAC(src, key):
	plain = b64_encoder(src)[0].encode()
	key = hex_encoder(key)[0].encode()
	key_bitlen = len(key)*4
	
	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{}'.format(256, key)
	retcode, out, er__ = openssl(cmd, prefix, True)
	mac = out.split(' ')[1][:-1]
	return bytes(hex_decoder(mac)[0])
	
def beltHash(src):
	plain = b64_encoder(src)[0].encode()

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -belt-hash'.format()
	retcode, out, er__ = openssl(cmd, prefix, True)
	hash_ = out.split(' ')[1][:-1]
	return bytes(hex_decoder(hash_)[0])



