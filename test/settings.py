# *****************************************************************************
# \file settings.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A settings needed for testing
# \created 2020.01.27
# \version 2020.01.29
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

import codecs

hex_encoder = codecs.getencoder('hex')
b64_encoder = codecs.getencoder('base64')
hex_decoder = codecs.getdecoder('hex')
b64_decoder = codecs.getdecoder('base64')
