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
from belt import *

def test_version():
	retcode, out, __ = openssl('version', True)
	assert retcode == 0
	print(out)

def test_engine():
	retcode, out, __ = openssl('engine -c -t bee2evp', True)
	assert retcode == 0
	print(out)

def test_belt():
	belt = Belt_test("nopad")

	#Block
	#A.1 Encrypt
	ecb128_right_plain_msg = 'b194bac80a08f53b366d008e584a5de4'
	ecb128_right_enc_msg = '69cca1c93557c9e3d66bc3e0fa88fa6e'
	key = 'e9dee72c8f0c0fa62ddb49f46f739647' + '06075316ed247a3739cba38303a98bf6'
	belt.beltBlockEncr(ecb128_right_plain_msg, ecb128_right_enc_msg, key, 128)
	#A.4 Decrypt
	ecb128_right_plain_msg = '0dc5300600cab840b38448e5e993f421'
	ecb128_right_enc_msg = 'e12bdc1ae28257ec703fccf095ee8df1'
	key = '92bd9b1ce5d141015445fbc95e4d0ef2' + '682080aa227d642f2687f93490405511'
	belt.beltBlockDecr(ecb128_right_plain_msg, ecb128_right_enc_msg, key, 128)
	
	#ECB
	#A.6 Encrypt
	ecb384_right_plain_msg = 'b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d' + '5be3d61217b96181fe6786ad716b890b'
	ecb384_right_enc_msg = '69cca1c93557c9e3d66bc3e0fa88fa6e' + '5f23102ef109710775017f73806da9dc' + '46fb2ed2ce771f26dcb5e5d1569f9ab0'
	key = 'e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6'
	belt.beltECBEncr(ecb384_right_plain_msg.lower(), ecb384_right_enc_msg.lower(), key, 384)
	#A.8 Decrypt	
	ecb384_right_plain_msg = 'b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d' + '5be3d61217b96181fe6786ad716b890b'
	ecb384_right_enc_msg = '69cca1c93557c9e3d66bc3e0fa88fa6e' + '5f23102ef109710775017f73806da9dc' + '46fb2ed2ce771f26dcb5e5d1569f9ab0'
	key = 'e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6'
	belt.beltECBDecr(ecb384_right_plain_msg.lower(), ecb384_right_enc_msg.lower(), key.lower(), 384)

	#CBC
	#A.10 Encrypt
	cbc384_right_plain_msg = 'B194BAC80A08F53B366D008E584A5DE4' + '8504FA9D1BB6C7AC252E72C202FDCE0D' + '5BE3D61217B96181FE6786AD716B890B'
	cbc384_right_enc_msg = '10116EFAE6AD58EE14852E11DA1B8A74' + '5CF2480E8D03F1C19492E53ED3A70F60' + '657C1EE8C0E0AE5B58388BF8A68E3309'
	cbc384_iv = 'BE32971343FC9A48A02A885F194B09A1'
	key = 'E9DEE72C8F0C0FA62DDB49F46F739647' + '06075316ED247A3739CBA38303A98BF6'
	belt.beltCBCEncr(cbc384_right_plain_msg.lower(), cbc384_right_enc_msg.lower(), key.lower(), 384, cbc384_iv.lower())

	#A.12 Decrypt
	cbc384_right_plain_msg = '730894D6158E17CC1600185A8F411CAB' + '0471FF85C83792398D8924EBD57D03DB' + '95B97A9B7907E4B020960455E46176F8'
	cbc384_right_enc_msg = 'E12BDC1AE28257EC703FCCF095EE8DF1' + 'C1AB76389FE678CAF7C6F860D5BB9C4F' + 'F33C657B637C306ADD4EA7799EB23D31' 
	cbc384_iv = '7ECDA4D01544AF8CA58450BF66D2E88A'
	key = '92BD9B1CE5D141015445FBC95E4D0EF2' + '682080AA227D642F2687F93490405511'
	belt.beltCBCEncr(cbc384_right_plain_msg.lower(), cbc384_right_enc_msg.lower(), key.lower(), 384, cbc384_iv.lower())

	#CFB
	#A.14 Encrypt
	cfb384_right_plain_msg = 'B194BAC80A08F53B366D008E584A5DE4' + '8504FA9D1BB6C7AC252E72C202FDCE0D' + '5BE3D61217B96181FE6786AD716B890B'
	cfb384_right_enc_msg = 'C31E490A90EFA374626CC99E4B7B8540' + 'A6E48685464A5A06849C9CA769A1B0AE' + '55C2CC5939303EC832DD2FE16C8E5A1B'
	cfb384_iv = 'BE32971343FC9A48A02A885F194B09A1'
	key = 'E9DEE72C8F0C0FA62DDB49F46F739647' + '06075316ED247A3739CBA38303A98BF6'
	belt.beltCFBEncr(cfb384_right_plain_msg.lower(), cfb384_right_enc_msg.lower(), key.lower(), 384, cfb384_iv.lower())

	#A.15 Decrypt
	cfb384_right_plain_msg = 'FA9D107A86F375EE65CD1DB881224BD0' + '16AFF814938ED39B3361ABB0BF0851B6' + '52244EB06842DD4C94AA4500774E40BB'
	cfb384_right_enc_msg = 'E12BDC1AE28257EC703FCCF095EE8DF1' + 'C1AB76389FE678CAF7C6F860D5BB9C4F' + 'F33C657B637C306ADD4EA7799EB23D31' 
	cfb384_iv = '7ECDA4D01544AF8CA58450BF66D2E88A'
	key = '92BD9B1CE5D141015445FBC95E4D0EF2' + '682080AA227D642F2687F93490405511'
	belt.beltCFBDecr(cfb384_right_plain_msg.lower(), cfb384_right_enc_msg.lower(), key.lower(), 384, cfb384_iv.lower())

	#CTR
	#A.16
	ctr384_right_plain_msg = 'B194BAC80A08F53B366D008E584A5DE4' + '8504FA9D1BB6C7AC252E72C202FDCE0D' + '5BE3D61217B96181FE6786AD716B890B'
	ctr384_right_enc_msg = '52C9AF96FF50F64435FC43DEF56BD797' + 'D5B5B1FF79FB41257AB9CDF6E63E81F8' + 'F00341473EAE409833622DE05213773A'
	ctr384_iv = 'BE32971343FC9A48A02A885F194B09A1'
	key = 'E9DEE72C8F0C0FA62DDB49F46F739647' + '06075316ED247A3739CBA38303A98BF6'
	belt.beltCTREncr(ctr384_right_plain_msg.lower(), ctr384_right_enc_msg.lower(), key.lower(), 384, ctr384_iv.lower())

	#MAC
	#A.18
	mac384_right_input = 'B194BAC80A08F53B366D008E584A5DE4' + '8504FA9D1BB6C7AC252E72C202FDCE0D' + '5BE3D61217B96181FE6786AD716B890B'
	mac384_right_mac = '2DAB59771B4B16D0'
	key = 'E9DEE72C8F0C0FA62DDB49F46F739647' + '06075316ED247A3739CBA38303A98BF6'
	belt.beltMAC(mac384_right_input.lower(), mac384_right_mac.lower(), key.lower(), 384)

	#HASH
	#A.25
	hash256_right_plain_msg = 'B194BAC80A08F53B366D008E584A5DE4' + '8504FA9D1BB6C7AC252E72C202FDCE0D'
	hash254_right_hash = '749E4C3653AECE5E48DB4761227742EB' + '6DBE13F4A80F7BEFF1A9CF8D10EE7786'
	belt.beltHash(hash256_right_plain_msg.lower(), hash254_right_hash.lower())


if __name__ == '__main__':
	test_version()
	test_engine()
	#test_belt()

	
