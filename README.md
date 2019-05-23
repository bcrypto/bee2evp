Bee2evp: an engine for OpenSSL
==============================

What is Bee2evp?
----------------

Bee2evp is a cryptographic library which connects Bee2 (see 
[github.com/agievich/bee2](https://github.com/agievich/bee2))
with OpenSSL. 
Bee2evp provides cryptographic services using EVP interfaces
(see [www.openssl.org/docs/crypto/evp.html]
(https://www.openssl.org/docs/crypto/evp.html)).

Bee2evp is organized as an engine of OpenSSL.

Build
-----

  mkdir build
  cd build
  cmake [-DCMAKE_BUILD_TYPE={Release|Debug|Coverage|ASan|ASanDbg|MemSan|MemSanDbg|Check}] ..
  make
  [make install]

Build types (Release by default):
   
*  Coverage -- test coverage, 
*  ASan, ASanDbg -- [address sanitizer](http://en.wikipedia.org/wiki/AddressSanitizer),
*  MemSan, MemSanDbg -- [memory sanitizer](http://code.google.com/p/memory-sanitizer/),
*  Check -- strict compile rules.

Preparations
------------

Before building Bee2evp, you should build and configure Bee2 and OpenSSL. 
Bee2evp requires OpenSSL version 1.1.0 or higher.

### Building Bee2

See instructions in [github.com/agievich/bee2](https://github.com/agievich/bee2).

### Building OpenSSL

1 Download the latest source files from [openssl.org/source](https://openssl.org/source).
2 Unpack files into some directory, for example, openssl-1.1.1.
3 Go to this directory.
4 Run the following commands:
    mkdir build
    cd build
    ../config 
    make
    make install

By default, OpenSSL {headers|binaries|libraries} will install 
in the directory /usr/local/{include|bin|lib}.

### Configuring OpenSSL

1 Rename /usr/local/ssl/openssl.dist -> /usr/local/ssl/openssl.cnf
2 Open /usr/local/lib/openssl.cnf
3 Add the following text (before the [new_oids] section):

    openssl_conf = openssl_init

    [openssl_init]
    engines = engine_section

    [engine_section]
    bee2evp = bee2evp_section

    [bee2evp_section]
    engine_id = bee2evp
    dynamic_path = /usr/local/lib/libbee2evp.so
    default_algorithms = ALL

### Using OpenSSL

/usr/local/bin/openssl

License
-------

Bee2evp is released under the terms of the GNU General Public License version 3
(GNU GPLv3) with the additional exemption that compiling, linking, 
and/or using OpenSSL is allowed. See [LICENSE](LICENSE) for more information.
