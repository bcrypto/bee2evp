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

echo $1
cd "$( dirname "${BASH_SOURCE[0]}" )"

openssl_branch=$1

is_openssl_3() {
  if [[ "$openssl_branch" =~ .*[-_]([0-9]).* ]];
  then
    openssl_major_version="${BASH_REMATCH[1]}"
  else
    openssl_major_version="${BASH_REMATCH[1]}"
  fi
}

is_openssl_3

if [[ "$openssl_major_version" == "3" ]];
then
    # source source3.sh $1
    # test_bee2evp
  source source3.sh $1
  echo "in3"
  # clean && update_repos && patch_openssl && \
  # build_bee2 && build_openssl && build_bee2evp && attach_bee2evp
  build_bee2evp && attach_bee2evp
    # test_bee2evp
else
  source source.sh $1
  echo "in1.1.1"
  clean && update_repos && patch_openssl && \
    build_bee2 && build_openssl && build_bee2evp && attach_bee2evp
    # test_bee2evp
fi
