#!/bin/bash
# *****************************************************************************
# \file build.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Common build script
# \created 2025.11.11
# \version 2025.11.13
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

scripts_dir="$( dirname "${BASH_SOURCE[0]}" )"
source $scripts_dir/source.sh

default_opt

while [[ $# -gt 0 ]]; do
  parse_opt $1
  shift
done

check_opt

is_openssl_3 

set_dir

system_opt

if $enable_setup; then
  setup
fi

if $enable_build; then
  build
fi

if $enable_test; then
  test_bee2evp
fi
