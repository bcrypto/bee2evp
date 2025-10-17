add_executable(testb2e
	aead_test.c
	hmac_test.c
	hkdf_test.c
	test.c
)
target_link_libraries(testb2e  ${libs})

add_test(testb2e testb2e)