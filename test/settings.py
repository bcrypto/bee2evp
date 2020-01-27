import codecs

hex_encoder = codecs.getencoder('hex')
b64_encoder = codecs.getencoder('base64')
hex_decoder = codecs.getdecoder('hex')
b64_decoder = codecs.getdecoder('base64')