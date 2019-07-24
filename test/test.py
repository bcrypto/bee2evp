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
	retcode, out, er__ = openssl('version', True)
	assert retcode == 0
	print(out)

def test_engine():
	retcode, out, er__ = openssl('engine -c -t bee2evp', True)
	assert retcode == 0
	print(out)

def test_cipher():
	plain_msg = bytearray.fromhex('b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b')
	with open("plain_msg.txt", "w") as f:
		f.write(plain_msg) 
	retcode, out, er__ = openssl('enc -belt-ecb256 -nopad -e -in plain_msg.txt -K e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6', True)
	encrypted_msg = out.encode("hex")
	assert encrypted_msg == '69cca1c93557c9e3d66bc3e0fa88fa6e5f23102ef109710775017f73806da9dc46fb2ed2ce771f26dcb5e5d1569f9ab0'
	print("encrypted message:\n" + encrypted_msg)

def test_hash():
	plain_msg = bytearray.fromhex('b194bac80a08f53b366d008e58')
	with open("plain_msg.txt", "w") as f:
		f.write(plain_msg)
	retcode, out, er__ = openssl('dgst -belt-hash -hex plain_msg.txt', True)
	hash_value = out.split(' ')[1].strip()
	assert hash_value == "abef9725d4c5a83597a367d14494cc2542f20f659ddfecc961a3ec550cba8c75"
	print(out)

if __name__ == '__main__':
	test_version()
	test_engine()
	test_cipher()
	test_hash()
