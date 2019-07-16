Bee2evp: an OpenSSL engine
==========================

[![Build Status](https://travis-ci.org/bcrypto/bee2evp.svg?branch=master)](https://travis-ci.org/bcrypto/bee2evp)

What is Bee2evp?
----------------

Bee2evp is a cryptographic library which encapsulates [Bee2](https://github.com/agievich/bee2)
into [OpenSSL](openssl.org). Bee2evp provides cryptographic services using the 
[EVP](https://wiki.openssl.org/index.php/EVP) interface. Bee2evp is organized 
as an OpenSSL engine.

Build
-----
```
mkdir build
cd build
cmake [-DCMAKE_BUILD_TYPE={Release|Debug|Coverage|ASan|ASanDbg|MemSan|MemSanDbg|Check}] ..
make
[make install]
```

Build types (Release by default):
   
*  Coverage -- test coverage; 
*  ASan, ASanDbg -- [address sanitizer](http://en.wikipedia.org/wiki/AddressSanitizer);
*  MemSan, MemSanDbg -- [memory sanitizer](http://code.google.com/p/memory-sanitizer/);
*  Check -- strict compile rules.

Preparations
------------

Before building Bee2evp, it is necessary to build and configure Bee2 and OpenSSL. 
Bee2evp requires OpenSSL version 1.1.0 or higher.

### Building Bee2

See instructions in [github.com/agievich/bee2](https://github.com/agievich/bee2).

### Building OpenSSL

1. Download the latest source files from [openssl.org/source](https://openssl.org/source).
2. Unpack files into some directory, for example, `openssl-1.1.1`.
3. Go to this directory.
4. Run the following commands:
   ```		
   mkdir build
   cd build
   ../config 
   make
   make install
   ```

By default, OpenSSL {headers|binaries|libraries} will be installed
in the directory `/usr/local/{include|bin|lib}`.

### Configuring OpenSSL

1. Rename `/usr/local/ssl/openssl.conf.dist` -> `/usr/local/ssl/openssl.cnf`.
2. Open `/usr/local/lib/openssl.cnf`.
3. Add the following text (before the `[new_oids]` section):
   ```
   openssl_conf = openssl_init
   [openssl_init]
   engines = engine_section
   [engine_section]
   bee2evp = bee2evp_section
   [bee2evp_section]
   engine_id = bee2evp
   dynamic_path = /usr/local/lib/libbee2evp.so
   default_algorithms = ALL
   ```
4. Make sure that `LD_LIBRARY_PATH` includes `/usr/local/lib`.
   
### Listing the capabilities

```
openssl engine -c -t bee2evp
```

License
-------

Bee2evp is released under the terms of the GNU General Public License version 3
(GNU GPLv3) with the additional exemption that compiling, linking, 
and/or using OpenSSL is allowed. See [LICENSE](LICENSE) for more information.
