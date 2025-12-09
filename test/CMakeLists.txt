add_executable(testb2e
	src/md_test.c
	src/aead_test.c
	src/belt_test.c
	src/hmac_test.c
	src/hkdf_test.c
	src/bign_test.c
	src/cert_test.c
	src/pbkdf_test.c
	src/test.c
)
target_link_libraries(testb2e  ${libs})

add_test(testb2e testb2e)
