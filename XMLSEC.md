# Начиная с версии 1.2.33, xmlsec поддерживает плагины для openssl.

Сборка
------

```
$ ./configure --with-openssl=<path to openssl dir builded with bee2evp> --prefix=<installation path>
$ make
$ make install
$ make check
```

Подпись
-------

Пример подписи при использовании engine: 
[https://www.aleksey.com/pipermail/xmlsec/2021/010434.html](https://www.aleksey.com/pipermail/xmlsec/2021/010434.html)

Но проблема в том, что при использовании даного метода xmlsec подгружает приватный ключ
следующим образом:
```c
	// файл https://github.com/lsh123/xmlsec/blob/master/src/openssl/app.c, функция xmlSecOpenSSLAppEngineKeyLoad

    /* load private key */
    pKey = ENGINE_load_private_key(engine, engineKeyId,
                                   (UI_METHOD *)UI_null(),
                                   NULL);
    if(pKey == NULL) {
        xmlSecOpenSSLError("ENGINE_load_private_key", NULL);
        goto done;
    }
```

Плагин bee2evp, не поддерживает данный метод, и поэтому при попытке загрузки ключа
выводится в консоль данное исключение. Но сразу есть вопросы, откуда брать 
`engineKeyId` и каким его устанавливать в нашем случае.

Есть реализация этого метода в плагине [pkcs11](https://github.com/OpenSC/libp11).

[https://github.com/OpenSC/libp11/blob/master/src/eng_front.c](https://github.com/OpenSC/libp11/blob/master/src/eng_front.c):
```c
static EVP_PKEY *load_privkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	ENGINE_CTX *ctx;
	EVP_PKEY *pkey;

	ctx = get_ctx(engine);
	if (!ctx)
		return 0;
	pkey = ctx_load_privkey(ctx, s_key_id, ui_method, callback_data);
#ifdef EVP_F_EVP_PKEY_SET1_ENGINE
	/* EVP_PKEY_set1_engine() is required for OpenSSL 1.1.x,
	 * but otherwise setting pkey->engine breaks OpenSSL 1.0.2 */
	if (pkey && !EVP_PKEY_set1_engine(pkey, engine)) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
#endif /* EVP_F_EVP_PKEY_SET1_ENGINE */
	return pkey;
}

static int bind_helper(ENGINE *e) {
	...
	!ENGINE_set_load_privkey_function(e, load_privkey))
	...
}
```

[https://github.com/OpenSC/libp11/blob/master/src/eng_back.c](https://github.com/OpenSC/libp11/blob/master/src/eng_back.c):
```c
EVP_PKEY *ctx_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	PKCS11_KEY *key;

	key = ctx_load_object(ctx, "private key", match_private_key, s_key_id,
		ui_method, callback_data);
	if (!key) {
		ctx_log(ctx, 0, "PKCS11_get_private_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PRIVKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return PKCS11_get_private_key(key);
}


static void *ctx_load_object(ENGINE_CTX *ctx,
		const char *object_typestr,
		void *(*match_func)(ENGINE_CTX *, PKCS11_TOKEN *,
				const unsigned char *, size_t, const char *),
		const char *object_uri, UI_METHOD *ui_method, void *callback_data)
{
	void *obj = NULL;

	pthread_mutex_lock(&ctx->lock);

	/* Delayed libp11 initialization */
	if (ctx_init_libp11_unlocked(ctx)) {
		ENGerr(ENG_F_CTX_LOAD_OBJECT, ENG_R_INVALID_PARAMETER);
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	if (!ctx->force_login) {
		ERR_clear_error();
		obj = ctx_try_load_object(ctx, object_typestr, match_func,
			object_uri, 0, ui_method, callback_data);
	}

	if (!obj) {
		/* Try again with login */
		ERR_clear_error();
		obj = ctx_try_load_object(ctx, object_typestr, match_func,
			object_uri, 1, ui_method, callback_data);
		if (!obj) {
			ctx_log(ctx, 0, "The %s was not found at: %s\n",
				object_typestr, object_uri);
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	return obj;
}
```


