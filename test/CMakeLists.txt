add_executable(testb2e
	md_test.c
	aead_test.c
	belt_test.c
	hmac_test.c
	hkdf_test.c
	bign_test.c
	test.c
)
target_link_libraries(testb2e  ${libs})

add_test(testb2e testb2e)