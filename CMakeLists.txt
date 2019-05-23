cmake_minimum_required(VERSION 2.6)
project(BEE2EVP C)

set(BEE2EVP_VERSION_MAJOR "1")
set(BEE2EVP_VERSION_MINOR "0")
set(BEE2EVP_VERSION_PATCH "3")
set(BEE2EVP_VERSION "${BEE2EVP_VERSION_MAJOR}.${BEE2EVP_VERSION_MINOR}.${BEE2EVP_VERSION_PATCH}")

option(BUILD_DOC "Build documentation (doxygen required)." OFF)
option(INSTALL_HEADERS "Install headers." ON)

string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")

if(CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
      CACHE STRING "Choose the type of build: Release Debug Coverage ASan ASanDbg MemSan MemSanDbg Check"
      FORCE)
else()
  set(CMAKE_BUILD_TYPE Release
      CACHE STRING "Choose the type of build: Release Debug Coverage ASan ASanDbg MemSan MemSanDbg Check"
      FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -W -Wdeclaration-after-statement -Wwrite-strings -Wlogical-op -Wno-parentheses -Wno-unused-parameter -Wno-strict-aliasing")
  set(CMAKE_C_FLAGS_RELEASE     "-O2")
  set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
  set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 --coverage")
  set(CMAKE_C_FLAGS_ASAN        "-Werror -fsanitize=address -fno-common -O3")
  set(CMAKE_C_FLAGS_ASANDBG     "-Werror -fsanitize=address -fno-common -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls ")
  set(CMAKE_C_FLAGS_CHECK       "-Werror -O1 -Wcast-qual")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -W -Wdeclaration-after-statement -Wwrite-strings -Wpointer-arith -Wno-parentheses -Wno-unused-parameter -Wno-strict-aliasing")
  set(CMAKE_C_FLAGS_RELEASE     "-O2")
  set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
  set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 --coverage")
  set(CMAKE_C_FLAGS_ASAN        "-Werror -fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover -O3")
  set(CMAKE_C_FLAGS_ASANDBG     "-Werror -fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
  set(CMAKE_C_FLAGS_MEMSAN      "-Werror -fsanitize=memory -O3")
  set(CMAKE_C_FLAGS_MEMSANDBG   "-Werror -fsanitize=memory -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2")
  set(CMAKE_C_FLAGS_CHECK       "-Werror -O1")
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
  endif(CMAKE_COMPILER_IS_GNUCC)
  if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
  endif(CMAKE_COMPILER_IS_CLANG)
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

if(NOT LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR lib)
endif()

if(NOT BIN_INSTALL_DIR)
  set(BIN_INSTALL_DIR bin)
endif()

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL openssl>=1.1.0)

if(NOT OPENSSL_FOUND)
  message(WARNING 
    "Can't find the OpenSSL package. Suppose that OpenSSL exists...")
  set(OPENSSL_INCLUDE_DIR 
    /usr/local/include/
  )
  set(OPENSSL_LIBRARY_DIRS 
    /usr/local/lib/
  )
  set(OPENSSL_LIBRARIES
    /usr/local/lib/libcrypto.so /usr/local/lib/libssl.so
  )
endif()


if(NOT BEE2_INCLUDE_DIR)
  set(BEE2_INCLUDE_DIR 
    /usr/local/share/ 
  )
endif()

include_directories(
  include/
  src/
  ${BEE2_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR}
)

link_directories(${OPENSSL_LIBRARY_DIRS})

add_subdirectory(include)

set(src
  src/bee2evp.c
  src/belt_ameth.c
  src/belt_cipher.c
  src/belt_md.c
  src/belt_pbkdf.c
  src/belt_pmeth.c
  src/bign_ameth.c
  src/bign_asn1.c
  src/bign_pmeth.c
)

set(libs bee2 ${OPENSSL_LIBRARIES})

add_library(bee2evp SHARED ${src})
target_link_libraries(bee2evp ${libs})

# uncomment next lines to keep track of bee2evp.so with version numbers
# set_target_properties(bee2evp PROPERTIES 
#   VERSION ${BEE2EVP_VERSION_MAJOR}.${BEE2EVP_VERSION_MINOR}.${BEE2EVP_VERSION_PATCH}
#   SOVERSION 1.0)

install(TARGETS bee2evp
  DESTINATION ${LIB_INSTALL_DIR}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if(BUILD_DOC)
  add_subdirectory(doc)
endif()
