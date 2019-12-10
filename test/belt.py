#import numpy as np
from openssl import openssl
from binascii import b2a_base64, unhexlify

class Belt_test:

	def __init__(self, pad='nopad'):
		self.pad = pad

	def beltBlockEncr(self, right_plain_msg, right_enc_msg, key, msg_len):
		assert msg_len == 128
		plain_msg = right_plain_msg[:(msg_len/4)].decode('hex')
		with open("plain_msg.txt", "wb") as f:
			f.write(plain_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-ecb{} -{} -e -in {} -K {}'.format(key_bitlen, self.pad, 'plain_msg.txt', key)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltBlockDecr(self, right_plain_msg, right_enc_msg, key, msg_len):
		assert msg_len == 128
		enc_msg = right_enc_msg[:(msg_len/4)].decode('hex')
		with open("enc_msg.txt", "wb") as f:
			f.write(enc_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-ecb{} -{} -d -in {} -K {}'.format(key_bitlen, self.pad, 'enc_msg.txt', key)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_plain_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltECBEncr(self, right_plain_msg, right_enc_msg, key, msg_len):
		plain_msg = (right_plain_msg[:(msg_len/4)]).decode('hex')
		with open("plain_msg.txt", "wb") as f:
			f.write(plain_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-ecb{} -{} -e -in {} -K {}'.format(key_bitlen, self.pad, 'plain_msg.txt', key)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltECBDecr(self, right_plain_msg, right_enc_msg, key, msg_len):
		enc_msg = right_enc_msg[:(msg_len/4)].decode('hex')
		with open("enc_msg.txt", "wb") as f:
			f.write(enc_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-ecb{} -{} -d -in {} -K {}'.format(key_bitlen, self.pad, 'enc_msg.txt', key)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_plain_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltCBCEncr(self, right_plain_msg, right_enc_msg, key, msg_len, iv):
		plain_msg = (right_plain_msg[:(msg_len/4)]+'00').decode('hex')
		with open("plain_msg.txt", "wb") as f:
			f.write(plain_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-cbc{} -{} -e -in {} -K {} -iv {}'.format(key_bitlen, self.pad, 'plain_msg.txt', key, iv)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltCBCDecr(self, right_plain_msg, right_enc_msg, key, msg_len, iv):
		if (msg_len % 64 !=0):
			self.pad = '-nopad'
		enc_msg = right_enc_msg[:(msg_len/4)].decode('hex')
		with open("enc_msg.txt", "wb") as f:
			f.write(enc_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-cbc{} -{} -d -in {} -K {} -iv'.format(key_bitlen, self.pad, 'enc_msg.txt', key, iv)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_plain_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltCFBEncr(self, right_plain_msg, right_enc_msg, key, msg_len, iv):
		plain_msg = (right_plain_msg[:(msg_len/4)]+'00').decode('hex')
		with open("plain_msg.txt", "wb") as f:
			f.write(plain_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-cfb{} -{} -e -in {} -K {} -iv {}'.format(key_bitlen, self.pad, 'plain_msg.txt', key, iv)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltCFBDecr(self, right_plain_msg, right_enc_msg, key, msg_len, iv):
		if (msg_len % 64 !=0):
			self.pad = '-nopad'
		enc_msg = right_enc_msg[:(msg_len/4)].decode('hex')
		with open("enc_msg.txt", "wb") as f:
			f.write(enc_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-cfb{} -{} -d -in {} -K {} -iv {}'.format(key_bitlen, self.pad, 'enc_msg.txt', key, iv)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_plain_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltCTREncr(self, right_plain_msg, right_enc_msg, key, msg_len, iv):
		plain_msg = (right_plain_msg[:(msg_len/4)]+'00').decode('hex')
		with open("plain_msg.txt", "wb") as f:
			f.write(plain_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-ctr{} -{} -e -in {} -K {} -iv {} -nosalt'.format(key_bitlen, self.pad, 'plain_msg.txt', key, iv)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]
	

	def beltCTRDecr(self, right_plain_msg, right_enc_msg, key, msg_len, iv):
		if (msg_len % 64 !=0):
			self.pad = '-nopad'
		enc_msg = right_enc_msg[:(msg_len/4)].decode('hex')
		with open("enc_msg.txt", "wb") as f:
			f.write(enc_msg)
		key_bitlen = len(key)*4
		cmd = 'enc -belt-ctr{} -{} -d -in {} -K {} -iv {}'.format(key_bitlen, self.pad, 'enc_msg.txt', key, iv)
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		assert right_plain_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

	def beltMAC(self, right_input, right_mac, key, msg_len):
		plain_msg = right_input[:(msg_len/4)].decode('hex')
		with open("plain_msg.txt", "wb") as f:
			f.write(plain_msg)
		key_bitlen = len(key)*4
		cmd = 'dgst -mac belt-mac{} -macopt hexkey:{} {}'.format(256, key, 'plain_msg.txt')
		#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
		retcode, out, er__ = openssl(cmd, True)
		mac_ = out.split(' ')[1][:-1]
		assert right_mac == mac_

	def beltHash(self, right_plain_msg, right_hash):
		plain_msg = right_plain_msg.decode('hex')
		with open("plain_msg.txt", "wb") as f:
			f.write(plain_msg)
		cmd = 'dgst -belt-hash {}'.format('plain_msg.txt')
		retcode, out, er__ = openssl(cmd, True)
		hash_ = out.split(' ')[1][:-1]
		assert right_hash == hash_

