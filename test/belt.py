from openssl import openssl, OPENSSL_EXE_PATH

ECHO_EXE_PATH = '/bin/echo'

def beltBlockEncr(block, key):
	assert len(block) * 8 == 128

	plain = block.encode('base64')
	key = key.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block

def beltBlockDecr(block, key):
	assert len(block) * 8 == 128

	plain = block.encode('base64')
	key = key.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block

def beltECBEncr(right_plain_msg, right_enc_msg, key, msg_len):
	plain_msg = (right_plain_msg[:(msg_len/4)]).decode('hex')
	with open("plain_msg.txt", "wb") as f:
		f.write(plain_msg)
	key_bitlen = len(key)*4
	cmd = 'enc -belt-ecb{} -{} -e -salt -in {} -K {}'.format(key_bitlen, self.pad, 'plain_msg.txt', key)
	#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
	retcode, out, er__ = openssl(cmd, True)
	assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

def beltECBDecr(right_plain_msg, right_enc_msg, key, msg_len):
	enc_msg = right_enc_msg[:(msg_len/4)].decode('hex')
	with open("enc_msg.txt", "wb") as f:
		f.write(enc_msg)
	key_bitlen = len(key)*4
	cmd = 'enc -belt-ecb{} -{} -d -in {} -K {}'.format(key_bitlen, self.pad, 'enc_msg.txt', key)
	#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
	retcode, out, er__ = openssl(cmd, True)
	assert right_plain_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

def beltCBCEncr(right_plain_msg, right_enc_msg, key, msg_len, iv):
	plain_msg = (right_plain_msg[:(msg_len/4)]+'00').decode('hex')
	with open("plain_msg.txt", "wb") as f:
		f.write(plain_msg)
	key_bitlen = len(key)*4
	cmd = 'enc -belt-cbc{} -{} -e -in {} -K {} -iv {}'.format(key_bitlen, self.pad, 'plain_msg.txt', key, iv)
	#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
	retcode, out, er__ = openssl(cmd, True)
	assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

def beltCBCDecr(right_plain_msg, right_enc_msg, key, msg_len, iv):
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

def beltCFBEncr(right_plain_msg, right_enc_msg, key, msg_len, iv):
	plain_msg = (right_plain_msg[:(msg_len/4)]+'00').decode('hex')
	with open("plain_msg.txt", "wb") as f:
		f.write(plain_msg)
	key_bitlen = len(key)*4
	cmd = 'enc -belt-cfb{} -{} -e -in {} -K {} -iv {}'.format(key_bitlen, self.pad, 'plain_msg.txt', key, iv)
	#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
	retcode, out, er__ = openssl(cmd, True)
	assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]

def beltCFBDecr(right_plain_msg, right_enc_msg, key, msg_len, iv):
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

def beltCTREncr(right_plain_msg, right_enc_msg, key, msg_len, iv):
	plain_msg = (right_plain_msg[:(msg_len/4)]+'00').decode('hex')
	with open("plain_msg.txt", "wb") as f:
		f.write(plain_msg)
	key_bitlen = len(key)*4
	cmd = 'enc -belt-ctr{} -{} -e -in {} -K {} -iv {} -nosalt'.format(key_bitlen, self.pad, 'plain_msg.txt', key, iv)
	#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
	retcode, out, er__ = openssl(cmd, True)
	assert right_enc_msg[:(msg_len/4)] == out.encode('hex')[:(msg_len/4)]


def beltCTRDecr(right_plain_msg, right_enc_msg, key, msg_len, iv):
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

def beltMAC(right_input, right_mac, key, msg_len):
	plain_msg = right_input[:(msg_len/4)].decode('hex')
	with open("plain_msg.txt", "wb") as f:
		f.write(plain_msg)
	key_bitlen = len(key)*4
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{} {}'.format(256, key, 'plain_msg.txt')
	#retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
	retcode, out, er__ = openssl(cmd, True)
	mac_ = out.split(' ')[1][:-1]
	assert right_mac == mac_
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{} {}'.format(128, key[:32], 'plain_msg.txt')
	retcode, out, er__ = openssl(cmd, True)
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{} {}'.format(192, key[:48], 'plain_msg.txt')
	retcode, out, er__ = openssl(cmd, True)
	cmd = 'dgst -mac belt-hmac -macopt hexkey:{} {}'.format(key, 'plain_msg.txt')
	retcode, out, er__ = openssl(cmd, True)
	
def beltHash(right_plain_msg, right_hash):
	plain_msg = right_plain_msg.decode('hex')
	with open("plain_msg.txt", "wb") as f:
		f.write(plain_msg)
	cmd = 'dgst -belt-hash {}'.format('plain_msg.txt')
	retcode, out, er__ = openssl(cmd, True)
	hash_ = out.split(' ')[1][:-1]
	assert right_hash == hash_
	cmd = 'dgst -bash384 {}'.format('plain_msg.txt')
	retcode, out, er__ = openssl(cmd, True)
	cmd = 'dgst -bash512 {}'.format('plain_msg.txt')
	retcode, out, er__ = openssl(cmd, True)
	cmd = 'dgst -bash256 {}'.format('plain_msg.txt')
	retcode, out, er__ = openssl(cmd, True)



