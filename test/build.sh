#!/bin/bash
# *****************************************************************************
# \file build.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Build script
# \created 2024.05.31
# \version 2024.05.31
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

cd "$( dirname "${BASH_SOURCE[0]}" )"
source source.sh

install_prereq && clean && update_repos && patch_openssl &&\
  build_bee2 && build_openssl && build_bee2evp && attach_bee2evp
