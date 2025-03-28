#!/bin/bash
# *****************************************************************************
# \file build.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Build script
# \created 2024.06.07
# \version 2024.06.07
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

cd "$( dirname "${BASH_SOURCE[0]}" )/../test/"
bash build.sh $1
