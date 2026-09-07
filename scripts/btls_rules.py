# где (относительно этого файла) лежат большие фрагменты кода,
# определенные в правилах как payload_file.
SNIPPETS_DIR = "snippets"

_META = set(r"\.^$*+?()[]{}|")


def lit(text):
    return "".join("\\" + c if c in _META else c for c in text)


NEW = ">=3.5" # OpenSSL 3.5+ — исходники переформатированы clang-format.
OLD3 = ">=3.0,<3.5" # провайдеры, но старый стиль.
V3 = ">=3.0" # любая 3.x — там, где стиль не важен.
V111 = "<3.0" # 1.1.1 — до провайдеров

STDERR = ">=3.5.6" # печатает через BIO_printf,
STDOUT = "<3.5.6" # через printf

_CIPHERSUITES_OPT = """\
            if (!strcmp(opt_flag(), "-ciphersuites"))
            {
                if (!strcmp(opt_arg(), "TLS_BASH_PRG_AE2561_BASH256")) {
                    %s
                    default_cipher = tls13_bashprg2561bash_id;
                }
                if (!strcmp(opt_arg(), "TLS_BELT_CHE256_BELT_HASH")) {
                    %s
                    default_cipher = tls13_beltche256hbelt_id;
                }
            }
"""
_PRINT_STDERR = 'BIO_printf(bio_err, "Set default cipher %s\\n", opt_arg());'
_PRINT_STDOUT = 'printf("Set default cipher %s\\n", opt_arg());'
CIPHERSUITES_OPT_STDERR = _CIPHERSUITES_OPT % (_PRINT_STDERR, _PRINT_STDERR)
CIPHERSUITES_OPT_STDOUT = _CIPHERSUITES_OPT % (_PRINT_STDOUT, _PRINT_STDOUT)

HOIST_CCM_NEW = """\
        mode = EVP_CIPHER_get_mode(ciph);
        if (mode == EVP_CIPH_CCM_MODE) {
            uint32_t algenc;

            *ivlen = EVP_CCM_TLS_IV_LEN;
            if (s->s3.tmp.new_cipher != NULL) {
                algenc = s->s3.tmp.new_cipher->algorithm_enc;
            } else if (s->session->cipher != NULL) {
                /* We've not selected a cipher yet - we must be doing early data */
                algenc = s->session->cipher->algorithm_enc;
            } else if (s->psksession != NULL && s->psksession->cipher != NULL) {
                /* We must be doing early data with out-of-band PSK */
                algenc = s->psksession->cipher->algorithm_enc;
            } else {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
                return 0;
            }
"""

HOIST_NEW = """\
        *ivlen = EVP_CCM_TLS_IV_LEN;
        if (s->s3.tmp.new_cipher != NULL) {
            algenc = s->s3.tmp.new_cipher->algorithm_enc;
        } else if (s->session->cipher != NULL) {
            /* We've not selected a cipher yet - we must be doing early data */
            algenc = s->session->cipher->algorithm_enc;
        } else if (s->psksession != NULL && s->psksession->cipher != NULL) {
            /* We must be doing early data with out-of-band PSK */
            algenc = s->psksession->cipher->algorithm_enc;
        } else {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
            return 0;
        }

        mode = EVP_CIPHER_get_mode(ciph);
        if (mode == EVP_CIPH_CCM_MODE) {

"""

HOIST_CCM_OLD3 = """\
    mode = EVP_CIPHER_get_mode(ciph);
    if (mode == EVP_CIPH_CCM_MODE) {
        uint32_t algenc;

        *ivlen = EVP_CCM_TLS_IV_LEN;
        if (s->s3.tmp.new_cipher != NULL) {
            algenc = s->s3.tmp.new_cipher->algorithm_enc;
        } else if (s->session->cipher != NULL) {
            /* We've not selected a cipher yet - we must be doing early data */
            algenc = s->session->cipher->algorithm_enc;
        } else if (s->psksession != NULL && s->psksession->cipher != NULL) {
            /* We must be doing early data with out-of-band PSK */
            algenc = s->psksession->cipher->algorithm_enc;
        } else {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
            return 0;
        }
        if (algenc & (SSL_AES128CCM8 | SSL_AES256CCM8))
            *taglen = EVP_CCM8_TLS_TAG_LEN;
         else
"""

HOIST_OLD3 = """\
    *ivlen = EVP_CCM_TLS_IV_LEN;
    if (s->s3.tmp.new_cipher != NULL) {
        algenc = s->s3.tmp.new_cipher->algorithm_enc;
    } else if (s->session->cipher != NULL) {
        /* We've not selected a cipher yet - we must be doing early data */
        algenc = s->session->cipher->algorithm_enc;
    } else if (s->psksession != NULL && s->psksession->cipher != NULL) {
        /* We must be doing early data with out-of-band PSK */
        algenc = s->psksession->cipher->algorithm_enc;
    } else {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        return 0;
    }

    mode = EVP_CIPHER_get_mode(ciph);
    if (mode == EVP_CIPH_CCM_MODE) {
        if (algenc & (SSL_AES128CCM8 | SSL_AES256CCM8))
            *taglen = EVP_CCM8_TLS_TAG_LEN;
        else
"""

HOIST_CCM_V111 = """\
    if (EVP_CIPHER_mode(ciph) == EVP_CIPH_CCM_MODE) {
        uint32_t algenc;

        ivlen = EVP_CCM_TLS_IV_LEN;
        if (s->s3->tmp.new_cipher != NULL) {
            algenc = s->s3->tmp.new_cipher->algorithm_enc;
        } else if (s->session->cipher != NULL) {
            /* We've not selected a cipher yet - we must be doing early data */
            algenc = s->session->cipher->algorithm_enc;
        } else if (s->psksession != NULL && s->psksession->cipher != NULL) {
            /* We must be doing early data with out-of-band PSK */
            algenc = s->psksession->cipher->algorithm_enc;
        } else {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_DERIVE_SECRET_KEY_AND_IV,
                     ERR_R_EVP_LIB);
            goto err;
        }
        if (algenc & (SSL_AES128CCM8 | SSL_AES256CCM8))
            taglen = EVP_CCM8_TLS_TAG_LEN;
         else
"""

HOIST_V111 = """
    ivlen = EVP_CCM_TLS_IV_LEN;
    if (s->s3->tmp.new_cipher != NULL) {
        algenc = s->s3->tmp.new_cipher->algorithm_enc;
    } else if (s->session->cipher != NULL) {
        /* We've not selected a cipher yet - we must be doing early data */
        algenc = s->session->cipher->algorithm_enc;
    } else if (s->psksession != NULL && s->psksession->cipher != NULL) {
        /* We must be doing early data with out-of-band PSK */
        algenc = s->psksession->cipher->algorithm_enc;
    } else {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_DERIVE_SECRET_KEY_AND_IV,
                 ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_CIPHER_mode(ciph) == EVP_CIPH_CCM_MODE) {
        if (algenc & (SSL_AES128CCM8 | SSL_AES256CCM8))
            taglen = EVP_CCM8_TLS_TAG_LEN;
        else
"""


SSL_ARGS_BLOCK = (
    r"!sk_OPENSSL_STRING_push\(ssl_args, opt_arg\(\)\)\) \{\n"
    r"[ \t]*BIO_printf\(bio_err, \"%s: Memory allocation failure\\n\", prog\);\n"
    r"[ \t]*goto end;\n"
    r"[ \t]*\}\n")

# Правила. Схема ключей:
# id: уникальный идентификатор правила.
# desc: описание.
# file: путь относительно openssl диреткории.
# op: операция, одно из insert_after, insert_before, replace, append_file.
# anchor: регулярка, которая задает место правки.
# payload: что вставить или payload_file
# payload_file: имя файла в snippets
# guard: строка признак применения правила
# guard_re: регуляка как признак применения правила
# when: предикат версии openssl, без него правило для всех
# conditions: список альтернативного кода в зависимости от условий
# count: сколько совпажений anchor обработать
# flags: флаги регулярки
RULES = [
    # apps/

    # Идентификаторы.
    {
        "id": "apps_h.tls13_ids",
        "desc": "объявление идентификаторов криптонаборов TLS 1.3 BTLS",
        "op": "insert_after",
        "anchor": r"extern const unsigned char tls13_aes256gcmsha384_id\[\];\n",
        "guard": "tls13_beltche256hbelt_id",
        "payload": (
            "extern const unsigned char tls13_beltche256hbelt_id[];\n"
            "extern const unsigned char tls13_bashprg2561bash_id[];\n"
            "extern const unsigned char* default_cipher;\n"),
        "conditions": [
            {"when": V3, "file": "apps/include/apps.h"},
            {"when": V111, "file": "apps/apps.h"},
        ],
    },
    # Значения идентификаторов.
    {
        "id": "s_client.tls13_ids",
        "desc": "задаются значения для идентификаторов TLS 1.3 BTLS (0xFF1D/0xFF1E)",
        "file": "apps/s_client.c",
        "op": "insert_after",
        "anchor": r"const unsigned char tls13_aes256gcmsha384_id\[\] = \{ 0x13, 0x02 \};\n",
        "guard": "tls13_beltche256hbelt_id[] =",
        "payload": (
            "const unsigned char tls13_beltche256hbelt_id[] = { 0xFF, 0x1D };\n"
            "const unsigned char tls13_bashprg2561bash_id[] = { 0xFF, 0x1E };\n"
            "const unsigned char* default_cipher = tls13_aes128gcmsha256_id;\n"),
    },
    # Переопределение дефолтного криптонабора на стороне клиента.
    {
        "id": "s_client.ciphersuites_opt",
        "desc": "при парсе аргументов переопределяет дефолтный криптонабор"
                "если это один из TLS 1.3 BTLS",
        "file": "apps/s_client.c",
        "op": "insert_after",
        "anchor": SSL_ARGS_BLOCK,
        "guard": '!strcmp(opt_flag(), "-ciphersuites")',
        "conditions": [
            {"when": STDERR, "payload": CIPHERSUITES_OPT_STDERR},
            {"when": STDOUT, "payload": CIPHERSUITES_OPT_STDOUT},
        ],
    },
    # Использование дефолтного psk набора на стороне клиента.
    {
        "id": "s_client.psk_default_cipher",
        "desc": "при psk использовать не фиксированный,"
                "а дефолтный криптонабор (--ciphersuites переобпределяет дефолтный)",
        "file": "apps/s_client.c",
        "op": "replace",
        "anchor": r"cipher = SSL_CIPHER_find\(s, tls13_aes128gcmsha256_id\);",
        "guard": "SSL_CIPHER_find(s, default_cipher)",
        "payload": "cipher = SSL_CIPHER_find(s, default_cipher);",
    },
    # Переопределение дефолтного криптонабора на стороне сервера.
    {
        "id": "s_server.ciphersuites_opt",
        "desc": "при парсе аргументов переопределяет дефолтный криптонабор"
                "если это один из TLS 1.3 BTLS",
        "file": "apps/s_server.c",
        "op": "insert_after",
        "anchor": SSL_ARGS_BLOCK,
        "guard": '!strcmp(opt_flag(), "-ciphersuites")',
        "conditions": [
            {"when": STDERR, "payload": CIPHERSUITES_OPT_STDERR},
            {"when": STDOUT, "payload": CIPHERSUITES_OPT_STDOUT},
        ],
    },
    # Использование дефолтного psk набора на стороне сервера.
    {
        "id": "s_server.psk_default_cipher",
        "desc": "при psk использовать не фиксированный,"
                "а дефолтный криптонабор (--ciphersuites переобпределяет дефолтный)",
        "file": "apps/s_server.c",
        "op": "replace",
        "anchor": r"cipher = SSL_CIPHER_find\(ssl, tls13_aes128gcmsha256_id\);",
        "guard": "SSL_CIPHER_find(ssl, default_cipher)",
        "payload": "cipher = SSL_CIPHER_find(ssl, default_cipher);",
    },


    # crypto/

    # Только для версий 3.x. В архитектуре провайдеров путь от -pkeyopt до engine идёт через
    # таблицу трансляций параметров.

    # Трансляция params -> ctrl.
    {
        "id": "ctrl_params.fix_bign_ecx",
        "desc": "По заданному имени группы получаем ctrl команду:"
                "переводит bign-curve256v1 в NID и ложит в p1, без этого"
                "openssl genpkey -pkeyopt params:bign-curve256v1 не обработается при engine",
        "file": "crypto/evp/ctrl_params_translate.c",
        "when": V3,
        "op": "insert_before",
        "anchor": r"/\*-\n \* The translation table itself\n",
        "guard": "fix_bign_ecx",
        "payload_file": "fix_bign_ecx.c",
    },
    # Добавление записей в таблицу трансляций.
    {
        "id": "ctrl_params.bign_entries",
        "desc": "добавляем две записи в таблице трансляций: для генерации параметров и для генерации ключа",
        "file": "crypto/evp/ctrl_params_translate.c",
        "when": V3,
        "op": "replace",
        "anchor": (r"(    \{ (OSSL_ACTION_SET|SET), EVP_PKEY_X448, EVP_PKEY_X448,"
                   r" EVP_PKEY_OP_PARAMGEN, -1, NULL, NULL,\n"
                   r"[ ]+OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING,"
                   r" fix_group_ecx \},\n)"),
        "guard": "NID_bign_pubkey, NID_bign_pubkey, EVP_PKEY_OP_PARAMGEN",
        "payload": (
            "$1\n"
            "    { $2, NID_bign_pubkey, NID_bign_pubkey, EVP_PKEY_OP_PARAMGEN, -1, NULL, NULL,\n"
            "      OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, fix_bign_ecx },\n"
            "    { $2, NID_bign_pubkey, NID_bign_pubkey, EVP_PKEY_OP_KEYGEN, -1, NULL, NULL,\n"
            "      OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, fix_bign_ecx },\n"),
    },
    # Изменение условие на разборку PARAMETERS.
    {
        "id": "pem_pkey.params_without_key",
        "desc": "до: разбирали PARAMETERS только если задан запрашивали ключ,"
                "после: вдаже если не запрашивали (чтобы прочитать PEM с параметрами кривой bign)",
        "file": "crypto/pem/pem_pkey.c",
        "when": V3,
        "op": "replace",
        "anchor": (r"\} else if \(\(selection & EVP_PKEY_KEYPAIR\) == 0\n"
                   r"[ ]+&& \(slen = ossl_pem_check_suffix\(nm, \"PARAMETERS\"\)\) > 0\) \{"),
        "guard": '} else if ((slen = ossl_pem_check_suffix(nm, "PARAMETERS")) > 0) {',
        "payload": '} else if ((slen = ossl_pem_check_suffix(nm, "PARAMETERS")) > 0) {',
    },


    # include/openssl

    # Новый тип сертификата TLS_CT_BIGN_SIGN.
    {
        "id": "ssl3_h.ct_number",
        "desc": "увеличиваем счётчик типов сертификата",
        "file": "include/openssl/ssl3.h",
        "when": V3,
        "op": "replace",
        "anchor": r"(#[ ]*define[ ]+SSL3_CT_NUMBER[ ]+)12",
        "guard_re": r"#[ ]*define[ ]+SSL3_CT_NUMBER[ ]+13",
        "payload": "${1}13",
    },
    # Увеличиваем счётчик типов сертификата.
    {
        "id": "tls1_h.ct_number",
        "desc": "увеличиваем счётчик типов сертификата",
        "file": "include/openssl/tls1.h",
        "when": V3,
        "op": "replace",
        "anchor": r"(#[ ]*define[ ]+TLS_CT_NUMBER[ ]+)12",
        "guard_re": r"#[ ]*define[ ]+TLS_CT_NUMBER[ ]+13",
        "payload": "${1}13",
    },
    # Добавление TLS 1.3 BTLS криптонаборов в дефолтный список.
    {
        "id": "ssl_h.default_ciphersuites",
        "desc": "В 1.1.1 список криптонаборов TLS 1.3 по умолчанию задан макросом, добавляем TLS 1.3 BTLS криптонаборов",
        "file": "include/openssl/ssl.h",
        "when": V111,
        "op": "replace",
        "anchor": (r"(\"TLS_CHACHA20_POLY1305_SHA256:\" \\\n"
                   r"                                   )\"TLS_AES_128_GCM_SHA256\"\n"),
        "guard": '"TLS_BELT_CHE256_BELT_HASH:" \\',
        "payload": ('$1"TLS_AES_128_GCM_SHA256:" \\\n'
                    '                                   "TLS_BELT_CHE256_BELT_HASH:" \\\n'
                    '                                   "TLS_BASH_PRG_AE2561_BASH256"\n'),
    },
    # Добавление TLS 1.3 BTLS криптонаборов в дефолтный список.
    {
        "id": "ssl_h.default_ciphersuites_nochacha",
        "desc": "В 1.1.1 список криптонаборов TLS 1.3 по умолчанию задан макросом, добавляем TLS 1.3 BTLS криптонаборов"
                "при сбоорке без chacha20-poly1305",
        "file": "include/openssl/ssl.h",
        "when": V111,
        "op": "replace",
        "anchor": (r"(#  define TLS_DEFAULT_CIPHERSUITES \"TLS_AES_256_GCM_SHA384:\" \\\n"
                   r"                                   )\"TLS_AES_128_GCM_SHA256\"\n"),
        "guard_re": r"\"TLS_AES_128_GCM_SHA256\" \\\n",
        "payload": ('$1"TLS_AES_128_GCM_SHA256" \\\n'
                    '                                   "TLS_BELT_CHE256_BELT_HASH:" \\\n'
                    '                                   "TLS_BASH_PRG_AE2561_BASH256"\n'),
    },


    # providers/

    # Обновление групп.
    {
        "id": "capabilities.group_list",
        "desc": "Объявление 3 групп с идентификаторами 0xFE01/02/03 и уровнями стойкости"
                "128/192/256 бит, доступные в TLS 1.2 и 1.3",
        "file": "providers/common/capabilities.c",
        "op": "insert_after",
        "guard": "0xFE01",
        "conditions": [
            {"when": NEW,
             "anchor": r"    /\* 43 \*/ \{ OSSL_TLS_GROUP_ID_SecP384r1MLKEM1024,"
                       r" ML_KEM_1024_SECBITS, TLS1_3_VERSION, 0, -1, -1, 1 \},\n",
             "payload": (
                 "\t{ 0xFE01, 128, TLS1_2_VERSION, TLS1_3_VERSION, -1, -1, 0},\n"
                 "\t{ 0xFE02, 192, TLS1_2_VERSION, TLS1_3_VERSION, -1, -1, 0},\n"
                 "\t{ 0xFE03, 256, TLS1_2_VERSION, TLS1_3_VERSION, -1, -1, 0},\n")},
            {"when": OLD3,
             "anchor": r"    \{ OSSL_TLS_GROUP_ID_ffdhe8192, 192, TLS1_3_VERSION, 0, -1, -1 \},\n",
             "payload": (
                 "\t{ 0xFE01, 128, TLS1_2_VERSION, TLS1_3_VERSION, DTLS1_VERSION, DTLS1_2_VERSION},\n"
                 "\t{ 0xFE02, 192, TLS1_2_VERSION, TLS1_3_VERSION, -1, -1},\n"
                 "\t{ 0xFE03, 256, TLS1_2_VERSION, TLS1_3_VERSION, -1, -1},\n")},
        ],
    },
    # Делаем чтобы libssl находил наши группы.
    {
        "id": "capabilities.param_group_list",
        "desc": "делаем чтобы libssl находил наши группы",
        "file": "providers/common/capabilities.c",
        "guard": 'TLS_GROUP_ENTRY("bign-curve256v1"',
        "conditions": [
            {"when": NEW, "op": "insert_after",
             "anchor": r"#endif /\* !defined\(OPENSSL_NO_TLS_DEPRECATED_EC\) \*/\n",
             "payload": (
                 '    TLS_GROUP_ENTRY("bign-curve256v1", "bign-curve256v1", "bign-curve256v1", 44),\n'
                 '    TLS_GROUP_ENTRY("bign-curve384v1", "bign-curve384v1", "bign-curve384v1", 45),\n'
                 '    TLS_GROUP_ENTRY("bign-curve512v1", "bign-curve512v1", "bign-curve512v1", 46),\n')},
            {"when": OLD3, "op": "insert_before",
             "anchor": r"^\};\n#endif /\* !defined\(OPENSSL_NO_EC\) \|\| !defined\(OPENSSL_NO_DH\) \*/",
             "payload": (
                 '    TLS_GROUP_ENTRY("bign-curve256v1", "bign-curve256v1", "bign-curve256v1", 38),\n'
                 '    TLS_GROUP_ENTRY("bign-curve384v1", "bign-curve384v1", "bign-curve384v1", 39),\n'
                 '    TLS_GROUP_ENTRY("bign-curve512v1", "bign-curve512v1", "bign-curve512v1", 40),\n')},
        ],
    },

    # ssl/

    # Добавление btls.c.
    {
        "id": "build_info.btls_c",
        "desc": "добавление btls.c в список исходников libssl",
        "file": "ssl/build.info",
        "op": "replace",
        "guard": "btls.c",
        "conditions": [
            {"when": NEW, "anchor": r"        tls_depr\.c\n",
             "payload": "        tls_depr.c btls.c\n"},
            {"when": OLD3, "anchor": r"        tls_depr\.c\n",
             "payload": "        tls_depr.c\\\n        btls.c\n"},
            {"when": V111,
             "anchor": r"        statem/statem\.c record/ssl3_record_tls13\.c\n",
             "payload": "        statem/statem.c record/ssl3_record_tls13.c \\\n        btls.c\n"},
        ],
    },

    # ssl/record/
    # В 1.1.1 длина тега определялась в record; в 3.x эта логика находится в tls13_enc.c

    # btls.h
    {
        "id": "ssl3_record_tls13.include",
        "desc": "добавление в заголовок btls.h",
        "file": "ssl/record/ssl3_record_tls13.c",
        "when": V111,
        "op": "insert_after",
        "anchor": r"#include \"internal/cryptlib\.h\"\n",
        "guard": '#include "../btls.h"',
        "payload": '#include "../btls.h"\n#include <openssl/evp.h>\n',
    },
    # tag
    {
        "id": "ssl3_record_tls13.taglen",
        "desc": "добавление длин тегов для belt-che/bash-prg-ae",
        "file": "ssl/record/ssl3_record_tls13.c",
        "when": V111,
        "op": "replace",
        "anchor": (r"    \} else if \(alg_enc & SSL_CHACHA20\) \{\n"
                   r"        taglen = EVP_CHACHAPOLY_TLS_TAG_LEN;\n"
                   r"    \} else \{\n"),
        "guard": "EVP_BELTCHE_TLS_TAG_LEN",
        "payload": (
            "    } else if (alg_enc & SSL_CHACHA20) {\n"
            "        taglen = EVP_CHACHAPOLY_TLS_TAG_LEN;\n"
            "    } else if (alg_enc & SSL_BELTCHE) {\n"
            "\t\ttaglen = EVP_BELTCHE_TLS_TAG_LEN;\n"
            "\t} else if (alg_enc & SSL_BASHPRGAE) {\n"
            "\t\ttaglen = EVP_BASHPRGAE_TLS_TAG_LEN;\n"
            "\t} else {\n"),
    },

    # ssl/s3_lib.c

    # btls.h
    {
        "id": "s3_lib.include",
        "desc": "добавление btls.h в заголовок",
        "file": "ssl/s3_lib.c",
        "op": "replace",
        "anchor": r"\n\n#define TLS13_NUM_CIPHERS",
        "guard": '#include "btls.h"',
        "payload": '\n#include "btls.h"\n\n#define TLS13_NUM_CIPHERS',
    },
    # Криптонабора TLS 1.3.
    {
        "id": "s3_lib.tls13_ciphers",
        "desc": "добавление TLS 1.3 криптонаборов",
        "file": "ssl/s3_lib.c",
        "guard": "BTLS1_3_RFC_BELT_CHE256_BELT_HASH",
        "conditions": [
            {"when": NEW, "op": "insert_before",
             "anchor": r"^#endif\n\};\n\n/\*\n \* The list of available ciphers,",
             "payload_file": "tls13_ciphers.new.c"},
            {"when": OLD3, "op": "insert_before",
             "anchor": r"\n\};\n\n/\*\n \* The list of available ciphers,",
             "payload_file": "tls13_ciphers.old3.c"},
            {"when": V111, "op": "insert_before",
             "anchor": r"\n\};\n\n/\*\n \* The list of available ciphers,",
             "payload_file": "tls13_ciphers.v111.c"},
        ],
    },
    # TLS 1.2 криптонаборыю
    {
        "id": "s3_lib.ssl3_ciphers",
        "desc": "добавление TLS 1.2 криптонаборов",
        "file": "ssl/s3_lib.c",
        "op": "insert_before",
        "anchor": r"^\};\n\n/\*\n \* The list of known Signalling Cipher-Suite Value",
        "guard": "BTLS1_TXT_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT",
        "conditions": [
            {"when": NEW, "payload_file": "ssl3_ciphers.new.c"},
            {"when": "<3.5", "payload_file": "ssl3_ciphers.old.c"},
        ],
    },

    # mTLS.
    {
        "id": "s3_lib.req_cert_type",
        "desc": "для клиентской аутентификации ложим в пакет сообщение CertificateRequest и тип нашего сертификата",
        "file": "ssl/s3_lib.c",
        "guard": "alg_k & SSL_kBDHE",
        "conditions": [
            {"when": ">=3.3,<3.4", "op": "replace",
             "anchor": r"\n\n    if \(\(s->version == SSL3_VERSION\) && \(alg_k & SSL_kDHE\)\) \{",
             "payload": (
                 "\n"
                 "    if (s->version >= TLS1_VERSION && (alg_k & SSL_kBDHE))\n"
                 "            return WPACKET_put_bytes_u8(pkt, TLS_CT_BIGN_SIGN);\n"
                 "    if (s->version >= TLS1_VERSION && (alg_k & SSL_kBDHTPSK))\n"
                 "            return WPACKET_put_bytes_u8(pkt, TLS_CT_BIGN_SIGN);\n"
                 "    if ((s->version == SSL3_VERSION) && (alg_k & SSL_kDHE)) {")},
            {"op": "insert_before",
             "anchor": r"^    if \(\(s->version == SSL3_VERSION\) && \(alg_k & SSL_kDHE\)\) \{",
             "payload": (
                 "    if (s->version >= TLS1_VERSION && (alg_k & SSL_kBDHE))\n"
                 "            return WPACKET_put_bytes_u8(pkt, TLS_CT_BIGN_SIGN);\n"
                 "    if (s->version >= TLS1_VERSION && (alg_k & SSL_kBDHTPSK))\n"
                 "            return WPACKET_put_bytes_u8(pkt, TLS_CT_BIGN_SIGN);\n"
                 "\n")},
        ],
    },
    # Генерация параметров группы.
    {
        "id": "s3_lib.generate_param_group",
        "desc": "Для кастомных групп изначальный код только устанавливал тип ключа; для bign нужно сгенерировать доменные параметры кривой.",
        "file": "ssl/s3_lib.c",
        "when": V111,
        "op": "replace",
        "anchor": (r"        if \(pkey != NULL && EVP_PKEY_set_type\(pkey, ginf->nid\)\)\n"
                   r"            return pkey;\n"),
        "guard": "ginf->nid == NID_bign_curve256v1",
        "payload": (
            "        if (pkey != NULL && EVP_PKEY_set_type(pkey, ginf->nid)) {\n"
            "            if (ginf->nid == NID_bign_curve256v1 ||\n"
            "                ginf->nid == NID_bign_curve384v1 ||\n"
            "                ginf->nid == NID_bign_curve512v1\n"
            "            ) {\n"
            "                pctx = EVP_PKEY_CTX_new_id(ginf->nid, NULL);\n"
            "                if (pctx == NULL)\n"
            "                    goto err;\n"
            "                if (EVP_PKEY_paramgen_init(pctx) <= 0)\n"
            "                    goto err;\n"
            "                if (EVP_PKEY_paramgen(pctx, &pkey) <= 0) {\n"
            "                    EVP_PKEY_free(pkey);\n"
            "                    pkey = NULL;\n"
            "                }\n"
            "                EVP_PKEY_CTX_free(pctx);\n"
            "            }\n"
            "            return pkey;\n"
            "        }\n"),
    },

    # ssl/ssl_cert_table.h

    # btls.h
    {
        "id": "cert_table.include",
        "desc": "добавление btls.h в заголовок",
        "file": "ssl/ssl_cert_table.h",
        "guard": '#include "btls.h"',
        "conditions": [
            {"when": NEW, "op": "insert_after",
             "anchor": r"\* https://www\.openssl\.org/source/license\.html\n \*/\n",
             "payload": '#include "btls.h"\n'},
            {"when": OLD3, "op": "insert_before",
             "anchor": r"^static const SSL_CERT_LOOKUP ssl_cert_info",
             "payload": '#include "btls.h"\n'},
            {"when": V111, "op": "insert_before",
             "anchor": r"^static const SSL_CERT_LOOKUP ssl_cert_info",
             "payload": '#include "btls.h"\n\n'},
        ],
    },
    # SSL_PKEY_BIGN
    {
        "id": "cert_table.bign_slot",
        "desc": "мэппит тип ключа в битом аутентификации, "
                "без этого libssl не сможет загрузить bign-сертификат",
        "file": "ssl/ssl_cert_table.h",
        "op": "replace",
        "guard": "NID_bign_pubkey",
        "conditions": [
            {"when": NEW,
             "anchor": r"    \{ EVP_PKEY_ED448, SSL_aECDSA \} /\* SSL_PKEY_ED448 \*/",
             "payload": ("    { EVP_PKEY_ED448, SSL_aECDSA }, /* SSL_PKEY_ED448 */\n"
                         "    { NID_bign_pubkey, SSL_aBIGN } /* SSL_PKEY_BIGN */")},
            {"when": OLD3,
             "anchor": r"    \{EVP_PKEY_ED448, SSL_aECDSA\} /\* SSL_PKEY_ED448 \*/",
             "payload": ("    {EVP_PKEY_ED448, SSL_aECDSA}, /* SSL_PKEY_ED448 */\n"
                         "    {NID_bign_pubkey, SSL_aBIGN} /* SSL_PKEY_BIGN */")},
            {"when": V111,
             "anchor": r"    \{EVP_PKEY_ED448, SSL_aECDSA\} /\* SSL_PKEY_ED448 \*/",
             "payload": ("    {EVP_PKEY_ED448, SSL_aECDSA}, /* SSL_PKEY_ED448 */\n"
                         "    {NID_bign_pubkey, SSL_aBIGN}, /* SSL_PKEY_BIGN */")},
        ],
    },

    # ssl/ssl_ciph.c

    # btls.h
    {
        "id": "ssl_ciph.include",
        "desc": "добавление btls.h в заголовок",
        "file": "ssl/ssl_ciph.c",
        "guard": '#include "btls.h"',
        "conditions": [
            {"when": V3, "op": "replace",
             "anchor": r"\n\n/\* NB: make sure indices in these tables match values above \*/",
             "payload": ('\n#include "btls.h"\n'
                         "\n/* NB: make sure indices in these tables match values above */")},
            {"when": V111, "op": "insert_after",
             "anchor": r"#include \"internal/cryptlib\.h\"\n",
             "payload": '#include "btls.h"\n'},
        ],
    },
    # Enc list.
    {
        "id": "ssl_ciph.enc_num_idx",
        "desc": "Обновление счетчика алгоритмов шифрования",
        "file": "ssl/ssl_ciph.c",
        "when": V111,
        "op": "replace",
        "anchor": r"(#[ ]*define SSL_ENC_NUM_IDX[ ]+)22",
        "guard_re": r"#[ ]*define SSL_ENC_NUM_IDX[ ]+26",
        "payload": "${1}26",
    },
    {
        "id": "ssl_ciph.table_cipher",
        "desc": "мэппинг битов шифров в NID",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_after",
        "guard": "NID_belt_dwpt",
        "conditions": [
            {"when": NEW,
             "anchor": r"    \{ SSL_KUZNYECHIK, NID_kuznyechik_ctr_acpkm \}, /\* SSL_ENC_KUZNYECHIK_IDX \*/\n",
             "payload": (
                 "    { SSL_BELTDWP, NID_belt_dwpt }, /* SSL_ENC_BELTDWP_IDX 24 */\n"
                 "    { SSL_BELTCTR, NID_belt_ctrt }, /* SSL_ENC_BELTCTR_IDX 25 */\n"
                 "\t{ SSL_BELTCHE, NID_belt_chet },\n"
                 "\t{ SSL_BASHPRGAE, NID_bash_prg_aet }\n")},
            {"when": OLD3,
             "anchor": r"    \{SSL_KUZNYECHIK, NID_kuznyechik_ctr_acpkm\}, /\* SSL_ENC_KUZNYECHIK_IDX \*/\n",
             "payload": (
                 "    {SSL_BELTDWP, NID_belt_dwpt}, /* SSL_ENC_BELTDWP_IDX 24 */\n"
                 "    {SSL_BELTCTR, NID_belt_ctrt}, /* SSL_ENC_BELTCTR_IDX 25 */\n"
                 "\t{SSL_BELTCHE, NID_belt_chet},\n"
                 "\t{SSL_BASHPRGAE, NID_bash_prg_aet}\n")},
            {"when": V111,
             "anchor": r"    \{SSL_ARIA256GCM, NID_aria_256_gcm\}, /\* SSL_ENC_ARIA256GCM_IDX 21 \*/\n",
             "payload": (
                 "    {SSL_BELTCTR, NID_belt_ctrt}, /* SSL_ENC_BELTCTR_IDX 22 */\n"
                 "    {SSL_BELTDWP, NID_belt_dwpt}, /* SSL_ENC_BELTDWP_IDX 23 */\n"
                 "\t{SSL_BELTCHE, NID_belt_chet},\n"
                 "\t{SSL_BASHPRGAE, NID_bash_prg_aet},\n")},
        ],
    },
    {
        "id": "ssl_ciph.table_mac",
        "desc": "мэппинг дайджестов, их номера подставляются в поле algorithm2 криптонаборов",
        "file": "ssl/ssl_ciph.c",
        "op": "replace",
        "guard": "SSL_MD_BELTMAC_IDX",
        "conditions": [
            {"when": NEW,
             "anchor": r"    \{ SSL_KUZNYECHIKOMAC, NID_kuznyechik_mac \} /\* SSL_MD_KUZNYECHIKOMAC_IDX \*/\n",
             "payload": (
                 "    { SSL_KUZNYECHIKOMAC, NID_kuznyechik_mac }, /* SSL_MD_KUZNYECHIKOMAC_IDX */\n"
                 "    { SSL_BELTMAC, NID_belt_hash }, /* SSL_MD_BELTMAC_IDX 14 */\n"
                 "    { SSL_HBELT, NID_belt_hash }, /* SSL_MD_HBELT_IDX 15 */\n"
                 "    { SSL_BASH384, NID_bash384 }, /* SSL_MD_BASH384_IDX 16 */\n"
                 "\t{ SSL_BASH512, NID_bash512 }, /* SSL_MD_BASH512_IDX 17 */\n"
                 "    { SSL_BASH256, NID_bash256 } /* SSL_MD_BASH256_IDX 18 */\n")},
            {"when": OLD3,
             "anchor": lit("    {0, NID_sha512},            /* SSL_MD_SHA512_IDX 11 */\n")
                       + r"(.*?)"
                       + lit("    {SSL_KUZNYECHIKOMAC, NID_kuznyechik_mac}"
                             " /* SSL_MD_KUZNYECHIKOMAC_IDX */\n"),
             "payload": (
                 "    {0, NID_sha512},             /* SSL_MD_SHA512_IDX 11 */\n"
                 "$1"
                 "    {SSL_KUZNYECHIKOMAC, NID_kuznyechik_mac}, /* SSL_MD_KUZNYECHIKOMAC_IDX */\n"
                 "    {SSL_BELTMAC, NID_belt_hash}, /* SSL_MD_BELTMAC_IDX 14 */\n"
                 "    {SSL_HBELT, NID_belt_hash}, /* SSL_MD_HBELT_IDX 15 */\n"
                 "    {SSL_BASH384, NID_bash384}, /* SSL_MD_BASH384_IDX 16 */\n"
                 "\t{SSL_BASH512, NID_bash512}, /* SSL_MD_BASH512_IDX 17 */\n"
                 "    {SSL_BASH256, NID_bash256} /* SSL_MD_BASH256_IDX 18 */\n")},
            {"when": V111,
             "anchor": r"    \{0, NID_sha512\}             /\* SSL_MD_SHA512_IDX 11 \*/\n",
             "payload": (
                 "    {0, NID_sha512},             /* SSL_MD_SHA512_IDX 11 */\n"
                 "    {SSL_BELTMAC, NID_belt_mac256}, /* SSL_MD_BELTMAC_IDX 12 */\n"
                 "    {SSL_HBELT, NID_belt_hash}, /* SSL_MD_HBELT_IDX 13 */\n"
                 "    {SSL_BASH384, NID_bash384}, /* SSL_MD_BASH384_IDX 14 */\n"
                 "\t{SSL_BASH512, NID_bash512}, /* SSL_MD_BASH512_IDX 15 */\n"
                 "    {SSL_BASH256, NID_bash256} /* SSL_MD_BASH256_IDX 16 */\n")},
        ],
    },
    {
        "id": "ssl_ciph.table_auth_comma",
        "desc": "косметика, добавляет запятую после последнего элемента таблицы аутентификации",
        "file": "ssl/ssl_ciph.c",
        "when": OLD3,
        "op": "replace",
        "anchor": r"    \{SSL_aANY,    NID_auth_any\}\n",
        "guard": "{SSL_aANY,    NID_auth_any},",
        "payload": "    {SSL_aANY,    NID_auth_any},\n",
    },
    {
        "id": "ssl_ciph.digest_methods",
        "desc": "обновлеяем массив указателей на дайджесты в соответствии с количество SSL_MD_NUM_IDX",
        "file": "ssl/ssl_ciph.c",
        "when": V111,
        "op": "replace",
        "anchor": r"    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL\n",
        "guard": "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL",
        "payload": ("    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,"
                    " NULL, NULL, NULL, NULL, NULL, NULL, NULL\n"),
    },
    {
        "id": "ssl_ciph.table_kx",
        "desc": "обмен ключами",
        "file": "ssl/ssl_ciph.c",
        "op": "replace",
        "guard": "NID_kxbdhe",
        "conditions": [
            {"when": NEW, "anchor": r"    \{ SSL_kANY, NID_kx_any \}\n",
             "payload": ("    { SSL_kANY,      NID_kx_any },\n"
                         "    { SSL_kBDHE,     NID_kxbdhe },\n"
                         "    { SSL_kBDHT,     NID_kxbdht },\n"
                         "    { SSL_kBDHEPSK,  NID_kxbdhe_psk },\n"
                         "    { SSL_kBDHTPSK,  NID_kxbdht_psk }\n")},
            {"when": "<3.5", "anchor": r"    \{SSL_kANY,      NID_kx_any\}\n",
             "payload": ("    {SSL_kANY,      NID_kx_any},\n"
                         "    {SSL_kBDHE,     NID_kxbdhe},\n"
                         "    {SSL_kBDHT,     NID_kxbdht},\n"
                         "    {SSL_kBDHEPSK,  NID_kxbdhe_psk},\n"
                         "    {SSL_kBDHTPSK,  NID_kxbdht_psk}\n")},
        ],
    },
    {
        "id": "ssl_ciph.mac_pkey_id",
        "desc": "указываем ключом какого типа подписывается имитовставка",
        "file": "ssl/ssl_ciph.c",
        "op": "replace",
        "guard": "/* BELTMAC BELTHASH */",
        "conditions": [
            {"when": V3,
             "anchor": r"    NID_undef, NID_undef, NID_undef, NID_undef, NID_undef\n",
             "payload": ("    NID_undef, NID_undef, NID_undef, NID_undef, NID_undef,\n"
                         "    /* BELTMAC BELTHASH */\n"
                         "    NID_bign_pubkey, NID_bign_pubkey, NID_undef, NID_undef,"
                         " NID_undef\n")},
            {"when": V111,
             "anchor": r"    NID_undef, NID_undef, NID_undef\n\};",
             "payload": ("    NID_undef, NID_undef, NID_undef,\n"
                         "    /* BELTMAC BELTHASH */\n"
                         "    NID_undef, NID_undef\n};")},
        ],
    },
    {
        "id": "ssl_ciph.aliases_kx",
        "desc": "текстовые алиасы, которыми можно фильтровать из командной строки",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_after",
        "guard": "SSL_TXT_kBDHE",
        "conditions": [
            {"when": NEW, "anchor": r"    \{ 0, SSL_TXT_kGOST18, NULL, 0, SSL_kGOST18 \},\n",
             "payload": ("    { 0, SSL_TXT_kBDHE, NULL, 0, SSL_kBDHE },\n"
                         "    { 0, SSL_TXT_kBDHT, NULL, 0, SSL_kBDHT },\n"
                         "    { 0, SSL_TXT_kBDHEPSK, NULL, 0, SSL_kBDHEPSK },\n"
                         "    { 0, SSL_TXT_kBDHTPSK, NULL, 0, SSL_kBDHTPSK },\n")},
            {"when": OLD3, "anchor": r"    \{0, SSL_TXT_kGOST18, NULL, 0, SSL_kGOST18\},\n",
             "payload": ("    {0, SSL_TXT_kBDHE, NULL, 0, SSL_kBDHE},\n"
                         "    {0, SSL_TXT_kBDHT, NULL, 0, SSL_kBDHT},\n"
                         "    {0, SSL_TXT_kBDHEPSK, NULL, 0, SSL_kBDHEPSK},\n"
                         "    {0, SSL_TXT_kBDHTPSK, NULL, 0, SSL_kBDHTPSK},\n")},
            {"when": V111, "anchor": r"    \{0, SSL_TXT_kGOST, NULL, 0, SSL_kGOST\},\n",
             "payload": ("    {0, SSL_TXT_kBDHE, NULL, 0, SSL_kBDHE},\n"
                         "    {0, SSL_TXT_kBDHT, NULL, 0, SSL_kBDHT},\n"
                         "    {0, SSL_TXT_kBDHEPSK, NULL, 0, SSL_kBDHEPSK},\n"
                         "    {0, SSL_TXT_kBDHTPSK, NULL, 0, SSL_kBDHTPSK},\n")},
        ],
    },
    {
        "id": "ssl_ciph.aliases_auth",
        "desc": "текстовые алиасы, которыми можно фильтровать из командной строки",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_after",
        "guard": "SSL_TXT_aBIGN",
        "conditions": [
            {"when": NEW, "anchor": r"    \{ 0, SSL_TXT_aSRP, NULL, 0, 0, SSL_aSRP \},\n",
             "payload": "    { 0, SSL_TXT_aBIGN, NULL, 0, SSL_aBIGN },\n"},
            {"when": "<3.5", "anchor": r"    \{0, SSL_TXT_aSRP, NULL, 0, 0, SSL_aSRP\},\n",
             "payload": "    {0, SSL_TXT_aBIGN, NULL, 0, SSL_aBIGN},\n"},
        ],
    },
    {
        "id": "ssl_ciph.aliases_enc",
        "desc": "текстовые алиасы, которыми можно фильтровать из командной строки",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_after",
        "guard": "SSL_TXT_BELTDWP",
        "conditions": [
            {"when": NEW, "anchor": r"    \{ 0, SSL_TXT_CBC, NULL, 0, 0, 0, SSL_CBC \},\n",
             "payload": ("    { 0, SSL_TXT_BELTDWP, NULL, 0, 0, 0, SSL_BELTDWP },\n"
                         "    { 0, SSL_TXT_BELTCTR, NULL, 0, 0, 0, SSL_BELTCTR },\n"
                         "\t{ 0, SSL_TXT_BELTCHE, NULL, 0, 0, 0, SSL_BELTCHE },\n"
                         "\t{ 0, SSL_TXT_BASHPRGAE, NULL, 0, 0, 0, SSL_BASHPRGAE },\n")},
            {"when": OLD3, "anchor": r"    \{0, SSL_TXT_CBC, NULL, 0, 0, 0, SSL_CBC\},\n",
             "payload": ("    {0, SSL_TXT_BELTDWP, NULL, 0, 0, 0, SSL_BELTDWP},\n"
                         "    {0, SSL_TXT_BELTCTR, NULL, 0, 0, 0, SSL_BELTCTR},\n"
                         "\t{0, SSL_TXT_BELTCHE, NULL, 0, 0, 0, SSL_BELTCHE},\n"
                         "\t{0, SSL_TXT_BASHPRGAE, NULL, 0, 0, 0, SSL_BASHPRGAE},\n")},
            {"when": V111, "anchor": r"    \{0, SSL_TXT_ARIA256, NULL, 0, 0, 0, SSL_ARIA256GCM\},\n",
             "payload": ("    {0, SSL_TXT_BELTCTR, NULL, 0, 0, 0, SSL_BELTCTR},\n"
                         "    {0, SSL_TXT_BELTDWP, NULL, 0, 0, 0, SSL_BELTDWP},\n"
                         "    {0, SSL_TXT_BELTCHE, NULL, 0, 0, 0, SSL_BELTCHE},\n")},
        ],
    },
    {
        "id": "ssl_ciph.aliases_mac",
        "desc": "текстовые алиасы, которыми можно фильтровать из командной строки",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_after",
        "guard": "SSL_TXT_BELTMAC",
        "conditions": [
            {"when": NEW, "anchor": r"    \{ 0, SSL_TXT_GOST12, NULL, 0, 0, 0, 0, SSL_GOST12_256 \},\n",
             "payload": "    { 0, SSL_TXT_BELTMAC, NULL, 0, 0, 0, 0, SSL_BELTMAC },\n"},
            {"when": "<3.5", "anchor": r"    \{0, SSL_TXT_GOST12, NULL, 0, 0, 0, 0, SSL_GOST12_256\},\n",
             "payload": "    {0, SSL_TXT_BELTMAC, NULL, 0, 0, 0, 0, SSL_BELTMAC},\n"},
        ],
    },
    # Загрузка ciphers.
    {
        "id": "ssl_ciph.load_ciphers",
        "desc": "регистрируем belt-mac256 как mac с 32байтовым ключом,"
                "если движок не загружен, все наши наборы отключаются",
        "file": "ssl/ssl_ciph.c",
        "op": "replace",
        "guard": 'get_optional_pkey_id("BIGN")',
        "conditions": [
            {"when": NEW,
             "anchor": r"(^    if \(\(ctx->disabled_auth_mask & SSL_aGOST12\) ==[ ]+SSL_aGOST12\)\n"
                       r"        ctx->disabled_mkey_mask \|= SSL_kGOST18;\n\n)",
             "payload": (
                 "$1"
                 "    ctx->ssl_mac_pkey_id[SSL_MD_BELTMAC_IDX] = get_optional_pkey_id(\"belt-mac256\");\n"
                 "    if (ctx->ssl_mac_pkey_id[SSL_MD_BELTMAC_IDX]) {\n"
                 "        ctx->ssl_mac_secret_size[SSL_MD_BELTMAC_IDX] = 32;\n"
                 "    }\n\n"
                 "    if (!get_optional_pkey_id(\"BIGN\")){\n"
                 "        ctx->disabled_auth_mask |= SSL_aBIGN;\n"
                 "        ctx->disabled_mkey_mask |= SSL_kBDHE | SSL_kBDHT | SSL_kBDHEPSK | SSL_kBDHTPSK;\n"
                 "    }\n\n")},
            {"when": OLD3,
             "anchor": r"(^    if \(\(ctx->disabled_auth_mask & SSL_aGOST12\) ==[ ]+SSL_aGOST12\)\n"
                       r"        ctx->disabled_mkey_mask \|= SSL_kGOST18;\n\n)",
             "payload": (
                 "$1"
                 "    ctx->ssl_mac_pkey_id[SSL_MD_BELTMAC_IDX] = get_optional_pkey_id(\"belt-mac256\");\n"
                 "    if (ctx->ssl_mac_pkey_id[SSL_MD_BELTMAC_IDX]) {\n"
                 "        ctx->ssl_mac_secret_size[SSL_MD_BELTMAC_IDX] = 32;\n"
                 "        // ctx->ssl_mac_secret_size[SSL_MD_HBELT_IDX] = 32;\n"
                 "        // ctx->disabled_mac_mask ^= SSL_BELTMAC;\n"
                 "    }\n\n"
                 "    if (!get_optional_pkey_id(\"BIGN\")){\n"
                 "        ctx->disabled_auth_mask |= SSL_aBIGN;\n"
                 "        ctx->disabled_mkey_mask |= SSL_kBDHE | SSL_kBDHT | SSL_kBDHEPSK | SSL_kBDHTPSK;\n"
                 "    }\n\n")},
            {"when": V111,
             "anchor": r"^        \(SSL_aGOST01 \| SSL_aGOST12\)\)\n"
                       r"        disabled_mkey_mask \|= SSL_kGOST;\n\n",
             "payload": (
                 "        (SSL_aGOST01 | SSL_aGOST12))\n"
                 "        disabled_mkey_mask |= SSL_kGOST;\n\n"
                 "    ssl_mac_pkey_id[SSL_MD_BELTMAC_IDX] = get_optional_pkey_id(\"belt-mac256\");\n"
                 "    if (ssl_mac_pkey_id[SSL_MD_BELTMAC_IDX])\n"
                 "        ssl_mac_secret_size[SSL_MD_BELTMAC_IDX] = 32;\n\n"
                 "    if (!get_optional_pkey_id(\"BIGN\")){\n"
                 "        disabled_auth_mask |= SSL_aBIGN;\n"
                 "        disabled_mkey_mask |= SSL_kBDHE | SSL_kBDHT | SSL_kBDHEPSK | SSL_kBDHTPSK;\n"
                 "    }\n\n")},
        ],
    },
    {
        "id": "ssl_ciph.desc_kx",
        "desc": "читаемые имена",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_before",
        "anchor": r"    case SSL_kANY:\n        kx = \"any\";\n        break;\n",
        "guard": 'kx = "BDHE";',
        "payload": (
            "    case SSL_kBDHE:\n        kx = \"BDHE\";\n        break;\n"
            "    case SSL_kBDHT:\n        kx = \"BDHT\";\n        break;\n"
            "    case SSL_kBDHEPSK:\n        kx = \"BDHEPSK\";\n        break;\n"
            "    case SSL_kBDHTPSK:\n        kx = \"BDHTPSK\";\n        break;\n"),
    },
    {
        "id": "ssl_ciph.desc_auth",
        "desc": "читаемые имена",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_before",
        "anchor": r"    case SSL_aANY:\n        au = \"any\";\n        break;\n",
        "guard": 'au = "BIGN";',
        "payload": "    case SSL_aBIGN:\n        au = \"BIGN\";\n        break;\n",
    },
    {
        "id": "ssl_ciph.desc_enc",
        "desc": "читаемые имена",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_after",
        "anchor": (r"    case SSL_CHACHA20POLY1305:\n"
                   r"        enc = \"CHACHA20/POLY1305\(256\)\";\n        break;\n"),
        "guard": 'enc = "BELTCTR";',
        "conditions": [
            {"when": V3,
             "payload": (
                 "    case SSL_BELTCTR:\n        enc = \"BELTCTR\";\n        break;\n"
                 "    case SSL_BELTDWP:\n        enc = \"BELTDWP\";\n        break;\n"
                 "    case SSL_BELTCHE:\n        enc = \"BELCHE\";\n        break;\n"
                 "    case SSL_BASHPRGAE:\n        enc = \"BASHPRGAE\";\n        break;\n")},
            {"when": V111,
             "payload": (
                 "    case SSL_BELTCTR:\n        enc = \"BELTCTR\";\n        break;\n"
                 "    case SSL_BELTDWP:\n        enc = \"BELTDWP\";\n        break;\n"
                 "    case SSL_BELTCHE:\n        enc = \"BELTCHE\";\n        break;\n")},
        ],
    },
    {
        "id": "ssl_ciph.desc_mac",
        "desc": "читаемые имена",
        "file": "ssl/ssl_ciph.c",
        "op": "insert_after",
        "anchor": r"    case SSL_GOST12_512:\n        mac = \"GOST2012\";\n        break;\n",
        "guard": 'mac = "BELTMAC";',
        "payload": "    case SSL_BELTMAC:\n        mac = \"BELTMAC\";\n        break;\n",
    },
    {
        "id": "ssl_ciph.default_ciphersuites",
        "desc": "добавляем два BTLS TLS 1.3 криптонабора в дефолтный список",
        "file": "ssl/ssl_ciph.c",
        "when": V3,
        "op": "replace",
        "anchor": r"           \"TLS_AES_128_GCM_SHA256\";\n",
        "guard": "TLS_BELT_CHE256_BELT_HASH",
        "payload": ("           \"TLS_AES_128_GCM_SHA256:\"\n"
                    "           \"TLS_BELT_CHE256_BELT_HASH:\"\n"
                    "           \"TLS_BASH_PRG_AE2561_BASH256\";\n"),
    },

    # btls.h
    {
        "id": "ssl_init.include",
        "desc": "добавление btls.h",
        "file": "ssl/ssl_init.c",
        "op": "insert_after",
        "guard": '#include "btls.h"',
        "conditions": [
            {"when": V3, "anchor": r"#include \"internal/thread_once\.h\"\n"
                                   r"(?:#include \"internal/rio_notifier\.h\"[^\n]*\n)?",
             "payload": '#include "btls.h"\n'},
            {"when": V111, "anchor": r"#include \"internal/thread_once\.h\"\n",
             "payload": '#include "btls.h"\n'},
        ],
    },
    {
        "id": "ssl_init.btls_init",
        "desc": "инифиализация btls перед libcrypto",
        "file": "ssl/ssl_init.c",
        "guard": "btls_init()",
        "conditions": [
            {"when": ">=3.3,<3.4", "op": "replace",
             "anchor": r"#endif\n\n    if \(!OPENSSL_init_crypto\(opts, settings\)\)",
             "payload": ("#endif\n    if (!btls_init())\n        return 0;\n\n"
                         "    if (!OPENSSL_init_crypto(opts, settings))")},
            {"op": "insert_before",
             "anchor": r"    if \(!OPENSSL_init_crypto\(opts, settings\)\)\n        return 0;\n",
             "payload": "    if (!btls_init())\n        return 0;\n\n"},
        ],
    },
    {
        "id": "ssl_lib.include",
        "desc": "добавление btls.h",
        "file": "ssl/ssl_lib.c",
        "op": "insert_after",
        "guard": '#include "btls.h"',
        "conditions": [
            {"when": V3, "anchor": r"#include \"quic/quic_local\.h\"\n",
             "payload": '#include "btls.h"\n'},
            {"when": V111, "anchor": r"#include \"internal/refcount\.h\"\n",
             "payload": '#include "btls.h"\n'},
        ],
    },
    {
        "id": "ssl_lib.mask_bign",
        "desc": "разрешает bign-наборы, когда загружен bign-сертификат",
        "file": "ssl/ssl_lib.c",
        "op": "insert_before",
        "anchor": r"^    if \(rsa_enc\)\n        mask_k \|= SSL_kRSA;\n",
        "guard": "ssl_has_cert(s, SSL_PKEY_BIGN)",
        "payload": (
            "    if (ssl_has_cert(s, SSL_PKEY_BIGN)){\n"
            "        mask_k |= SSL_kBDHE | SSL_kBDHT | SSL_kBDHTPSK;\n"
            "        mask_a |= SSL_aBIGN;\n"
            "    }\n\n"),
    },
    {
        "id": "ssl_lib.mask_bdhepsk",
        "desc": "DHE-PSK-BIGN не нужен сертификат, поэтмоу всега доступен",
        "file": "ssl/ssl_lib.c",
        "op": "insert_before",
        "anchor": r"^#ifndef OPENSSL_NO_PSK\n    mask_k \|= SSL_kPSK;\n    mask_a \|= SSL_aPSK;\n",
        "guard": "OPENSSL_NO_BDHE_PSK",
        "conditions": [
            {"when": ">=3.3,<3.4",
             "payload": ("#ifndef OPENSSL_NO_BDHE_PSK\n"
                         "    mask_k |= SSL_kBDHEPSK;\n"
                         "#endif\n\n\n")},
            {"payload": ("#ifndef OPENSSL_NO_BDHE_PSK\n"
                         "    mask_k |= SSL_kBDHEPSK;\n"
                         "#endif\n\n")},
        ],
    },

    # ssl/ssl_local.h

    # btls.h
    {
        "id": "ssl_local.include",
        "desc": "добавление btls.h",
        "file": "ssl/ssl_local.h",
        "op": "replace",
        "guard": 'include "btls.h"',
        "anchor": r"\n\n(#([ ]*)ifdef OPENSSL_BUILD_SHLIBSSL)",
        "payload": '\n#${2}include "btls.h"\n\n$1',
    },
    {
        "id": "ssl_local.ssl_psk",
        "desc": "добавление psk криптонаборов",
        "file": "ssl/ssl_local.h",
        "op": "replace",
        "anchor": (r"(#[ ]*define SSL_PSK[ ]+\(SSL_kPSK \| SSL_kRSAPSK \| SSL_kECDHEPSK"
                   r" \| SSL_kDHEPSK)\)"),
        "guard": "SSL_kDHEPSK | SSL_kBDHEPSK | SSL_kBDHTPSK)",
        "payload": "$1 | SSL_kBDHEPSK | SSL_kBDHTPSK)",
    },
    {
        "id": "ssl_local.ssl_acert",
        "desc": "aBIGN требует сертификата",
        "file": "ssl/ssl_local.h",
        "op": "replace",
        "anchor": r"    \(SSL_aRSA \| SSL_aDSS \| SSL_aECDSA \| SSL_aGOST01 \| SSL_aGOST12\)",
        "guard": "SSL_aGOST12 | SSL_aBIGN)",
        "payload": "    (SSL_aRSA | SSL_aDSS | SSL_aECDSA | SSL_aGOST01 | SSL_aGOST12 | SSL_aBIGN)",
    },
    {
        "id": "ssl_local.max_digest",
        "desc": "обновление счетчика",
        "file": "ssl/ssl_local.h",
        "op": "replace",
        "conditions": [
            {"when": V3, "anchor": r"(#[ ]*define SSL_MAX_DIGEST[ ]+)14",
             "guard_re": r"#[ ]*define SSL_MAX_DIGEST[ ]+19", "payload": "${1}19"},
            {"when": V111, "anchor": r"(#[ ]*define SSL_MAX_DIGEST[ ]+)12",
             "guard_re": r"#[ ]*define SSL_MAX_DIGEST[ ]+17", "payload": "${1}17"},
        ],
    },
    {
        "id": "ssl_local.pkey_num",
        "desc": "обновление счетчика",
        "file": "ssl/ssl_local.h",
        "op": "replace",
        "anchor": r"(#[ ]*define SSL_PKEY_NUM[ ]+)9",
        "guard_re": r"#[ ]*define SSL_PKEY_NUM[ ]+10",
        "payload": "${1}10",
    },
    {
        "id": "ssl_local.enc_num_idx",
        "desc": "обновление счетчика",
        "file": "ssl/ssl_local.h",
        "when": V3,
        "op": "replace",
        "anchor": r"(#[ ]*define SSL_ENC_NUM_IDX[ ]+)24",
        "guard_re": r"#[ ]*define SSL_ENC_NUM_IDX[ ]+28",
        "payload": "${1}28",
    },

    # ssl/statem/

    {
        "id": "extensions_clnt.use_ecc",
        "desc": "заставляет клиента послать EC-расширения (список групп) для bign-наборов — иначе"
                "сервер не узнает, какие кривые клиент поддерживает",
        "file": "ssl/statem/extensions_clnt.c",
        "op": "replace",
        "guard": "SSL_kECDHEPSK | SSL_kBDHE",
        "conditions": [
            {"when": NEW, "anchor": r"if \(\(alg_k & \(SSL_kECDHE \| SSL_kECDHEPSK\)\)",
             "payload": "if ((alg_k & (SSL_kECDHE | SSL_kECDHEPSK | SSL_kBDHE | SSL_kBDHEPSK))"},
            {"when": "<3.5", "anchor": r"if \(\(alg_k & \(SSL_kECDHE \| SSL_kECDHEPSK\)\)",
             "guard": "SSL_kECDHEPSK | SSL_kBDHEPSK",
             "payload": "if ((alg_k & (SSL_kECDHE | SSL_kECDHEPSK | SSL_kBDHEPSK))"},
        ],
    },
    {
        "id": "extensions_srvr.etm",
        "desc": "отключает расширение etm для belt-ctr: этот режим несёт"
                "имитовставку по своим правилам, и штатная схема etm к нему неприменима",
        "file": "ssl/statem/extensions_srvr.c",
        "op": "replace",
        "guard": "algorithm_enc == SSL_BELTCTR",
        "conditions": [
            {"when": V3,
             "anchor": r"        \|\| s->s3\.tmp\.new_cipher->algorithm_enc == SSL_KUZNYECHIK\) \{",
             "payload": ("        || s->s3.tmp.new_cipher->algorithm_enc == SSL_KUZNYECHIK\n"
                         "        || s->s3.tmp.new_cipher->algorithm_enc == SSL_BELTCTR) {")},
            {"when": V111,
             "anchor": r"        \|\| s->s3->tmp\.new_cipher->algorithm_enc == SSL_eGOST2814789CNT12\) \{",
             "payload": ("        || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT12\n"
                         "        || s->s3->tmp.new_cipher->algorithm_enc == SSL_BELTCTR) {")},
        ],
    },
    {
        "id": "statem_clnt.key_exchange_expected",
        "desc": "клиент должен ожидать сообщение ServerKeyExchange для эфемерных и psk наборов"
                "Без этого он воспримет ServerKeyExchange как неожиданное сообщение и оборвёт связь",
        "file": "ssl/statem/statem_clnt.c",
        "op": "replace",
        "guard": "SSL_kBDHE | SSL_kBDHEPSK | SSL_kBDHTPSK",
        "conditions": [
            {"when": NEW,
             "anchor": r"    if \(alg_k & \(SSL_kDHE \| SSL_kECDHE \| SSL_kDHEPSK \| SSL_kECDHEPSK \| SSL_kSRP\)\) \{",
             "payload": ("    if (alg_k & (SSL_kDHE | SSL_kECDHE | SSL_kDHEPSK | SSL_kECDHEPSK |\n"
                         "        SSL_kSRP  | SSL_kBDHE | SSL_kBDHEPSK | SSL_kBDHTPSK)) {")},
            {"when": "<3.5",
             "anchor": r"                 \| SSL_kSRP\)\) \{",
             "payload": "                 | SSL_kSRP | SSL_kBDHE | SSL_kBDHEPSK | SSL_kBDHTPSK)) {"},
        ],
    },
    {
        "id": "statem_clnt.ske_psk_skip",
        "desc": "DHT-PSK-BIGN",
        "file": "ssl/statem/statem_clnt.c",
        "op": "replace",
        "anchor": r"    if \(alg_k & \(SSL_kPSK \| SSL_kRSAPSK\)\) \{",
        "guard": "SSL_kRSAPSK | SSL_kBDHTPSK)) {",
        "payload": "    if (alg_k & (SSL_kPSK | SSL_kRSAPSK | SSL_kBDHTPSK)) {",
    },
    {
        "id": "statem_clnt.process_ske",
        "desc": "парсим ServerKeyExchange",
        "file": "ssl/statem/statem_clnt.c",
        "op": "insert_before",
        "anchor": r"    \} else if \(alg_k\) \{\n        SSLfatal\(s, SSL_AD_UNEXPECTED_MESSAGE,",
        "guard": "btls_process_ske_bign_dhe",
        "payload": (
            "    } else if (alg_k & (SSL_kBDHE)) {\n"
            "        if (!btls_process_ske_bign_dhe(s, pkt, &pkey)) {\n"
            "            /* SSLfatal() already called */\n"
            "            goto err;\n"
            "        }\n"
            "    } else if (alg_k & SSL_kBDHEPSK) {\n"
            "        if (!btls_process_ske_psk_bign_dhe(s, pkt, &pkey)) {\n"
            "            /* SSLfatal() already called */\n"
            "            goto err;\n"
            "        }\n"),
    },
    {
        "id": "statem_clnt.construct_cke",
        "desc": " эфемерные наборы переиспользуют ecdhe openssl",
        "file": "ssl/statem/statem_clnt.c",
        "op": "insert_before",
        "anchor": r"    \} else if \(!\(alg_k & SSL_kPSK\)\) \{",
        "guard": "btls_construct_cke_bign_dht",
        "payload": (
            "    } else if (alg_k & (SSL_kBDHE | SSL_kBDHEPSK)) {\n"
            "        if (!tls_construct_cke_ecdhe(s, pkt))\n"
            "            goto err;\n"
            "    } else if (alg_k & (SSL_kBDHT | SSL_kBDHTPSK)) {\n"
            "        if (!btls_construct_cke_bign_dht(s, pkt))\n"
            "            goto err;\n"),
    },
    {
        "id": "statem_clnt.check_cert_bdhe",
        "desc": "для DHE-BIGN сервер обязан был прислать эфемерный ключ",
        "file": "ssl/statem/statem_clnt.c",
        "op": "replace",
        "guard": "alg_k & SSL_kBDHE) && (s->s3",
        "conditions": [
            {"when": ">=3.3,<3.4",
             "anchor": lit("        return 0;\n    }\n\n    return 1;\n}\n\n"
                           "#ifndef OPENSSL_NO_NEXTPROTONEG\n"),
             "payload": (
                 "        return 0;\n"
                 "    }\n"
                 "    if ((alg_k & SSL_kBDHE) && (s->s3.peer_tmp == NULL)) {\n"
                 "        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);\n"
                 "        return 0;\n"
                 "    }\n"
                 "    return 1;\n}\n\n"
                 "#ifndef OPENSSL_NO_NEXTPROTONEG\n")},
            {"when": V3,
             "anchor": lit("        return 0;\n    }\n\n    return 1;\n}\n\n"
                           "#ifndef OPENSSL_NO_NEXTPROTONEG\n"),
             "payload": (
                 "        return 0;\n"
                 "    }\n\n"
                 "    if ((alg_k & SSL_kBDHE) && (s->s3.peer_tmp == NULL)) {\n"
                 "        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);\n"
                 "        return 0;\n"
                 "    }\n"
                 "    return 1;\n}\n\n"
                 "#ifndef OPENSSL_NO_NEXTPROTONEG\n")},
            {"when": V111,
             "anchor": lit("    if ((alg_k & SSL_kDHE) && (s->s3->peer_tmp == NULL)) {\n"
                           "        SSLfatal(s, SSL_AD_INTERNAL_ERROR,"
                           " SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,\n"
                           "                 ERR_R_INTERNAL_ERROR);\n"
                           "        return 0;\n"
                           "    }\n"
                           "#endif\n\n"
                           "    return 1;\n}\n"),
             "payload": (
                 "    if ((alg_k & SSL_kDHE) && (s->s3->peer_tmp == NULL)) {\n"
                 "        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,\n"
                 "                 ERR_R_INTERNAL_ERROR);\n"
                 "        return 0;\n"
                 "    }\n"
                 "#endif\n"
                 "    if ((alg_k & SSL_kBDHE) && (s->s3->peer_tmp == NULL)) {\n"
                 "        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,\n"
                 "                 ERR_R_INTERNAL_ERROR);\n"
                 "        return 0;\n"
                 "    }\n"
                 "    return 1;\n}\n")},
        ],
    },
    {
        "id": "statem_srvr.send_ske",
        "desc": "отправляем SKE для DHE-BIGN и PSK вариантов",
        "file": "ssl/statem/statem_srvr.c",
        "op": "replace",
        "guard": "SSL_kRSAPSK | SSL_kBDHTPSK))",
        "conditions": [
            {"when": V3,
             "anchor": (r"        /\* Only send SKE if we have identity hint for plain PSK \*/\n"
                        r"        \|\| \(\(alg_k & \(SSL_kPSK \| SSL_kRSAPSK\)\)\n"
                        r"            && s->cert->psk_identity_hint\)\n"
                        r"        /\* For other PSK always send SKE \*/\n"
                        r"        \|\| \(alg_k & \(SSL_PSK & \(SSL_kDHEPSK \| SSL_kECDHEPSK\)\)\)\n"
                        r"#endif\n"
                        r"(#ifndef OPENSSL_NO_SRP\n"
                        r"        /\* SRP: send ServerKeyExchange \*/\n"
                        r"        \|\| \(alg_k & SSL_kSRP\)\n"
                        r"#endif\n)"),
             "payload": (
                 "        /* Only send SKE if we have identity hint for plain PSK or BDHTPSK */\n"
                 "        || ((alg_k & (SSL_kPSK | SSL_kRSAPSK | SSL_kBDHTPSK))\n"
                 "            && s->cert->psk_identity_hint)\n"
                 "        /* For other PSK always send SKE */\n"
                 "        || (alg_k & (SSL_PSK & (SSL_kDHEPSK | SSL_kECDHEPSK | SSL_kBDHEPSK)))\n"
                 "#endif\n"
                 "$1"
                 "        || (alg_k & SSL_kBDHE)\n")},
            {"when": V111,
             "anchor": (r"        /\* Only send SKE if we have identity hint for plain PSK \*/\n"
                        r"        \|\| \(\(alg_k & \(SSL_kPSK \| SSL_kRSAPSK\)\)\n"
                        r"            && s->cert->psk_identity_hint\)\n"
                        r"        /\* For other PSK always send SKE \*/\n"
                        r"        \|\| \(alg_k & \(SSL_PSK & \(SSL_kDHEPSK \| SSL_kECDHEPSK\)\)\)\n"
                        r"#endif\n"
                        r"(#ifndef OPENSSL_NO_SRP\n"
                        r"        /\* SRP: send ServerKeyExchange \*/\n"
                        r"        \|\| \(alg_k & SSL_kSRP\)\n"
                        r"#endif\n)"),
             "payload": (
                 "        /* Only send SKE if we have identity hint for plain PSK or BDHTPSK */\n"
                 "        || ((alg_k & (SSL_kPSK | SSL_kRSAPSK | SSL_kBDHTPSK))\n"
                 "            && s->cert->psk_identity_hint)\n"
                 "        /* For other PSK always send SKE */\n"
                 "        || (alg_k & (SSL_PSK & (SSL_kDHEPSK | SSL_kECDHEPSK | SSL_kBDHEPSK)))\n"
                 "#endif\n"
                 "$1"
                 "        || (alg_k & SSL_kBDHE)\n")},
        ],
    },
    {
        "id": "statem_srvr.ske_psk_skip",
        "desc": "",
        "file": "ssl/statem/statem_srvr.c",
        "op": "replace",
        "anchor": r"    if \(type & \(SSL_kPSK \| SSL_kRSAPSK\)\) \{",
        "guard": "SSL_kRSAPSK | SSL_kBDHTPSK)) {",
        "payload": "    if (type & (SSL_kPSK | SSL_kRSAPSK | SSL_kBDHTPSK)) {",
    },
    {
        "id": "statem_srvr.construct_ske",
        "desc": "сборка ServerKeyExchange",
        "file": "ssl/statem/statem_srvr.c",
        "guard": "btls_construct_ske_bign_dhe",
        "conditions": [
            {"when": NEW, "op": "insert_before",
             "anchor": r"        \} else\n#ifndef OPENSSL_NO_SRP\n            if \(type & SSL_kSRP\) \{",
             "payload": (
                 "        } else if (type & (SSL_kBDHE)) {\n"
                 "            if(!btls_construct_ske_bign_dhe(s, pkt))\n"
                 "                goto err;\n"
                 "        } else if (type & SSL_kBDHEPSK) {\n"
                 "            if(!btls_construct_ske_psk_bign_dhe(s, pkt))\n"
                 "                goto err;\n")},
            {"when": "<3.5", "op": "insert_before",
             "anchor": r"#ifndef OPENSSL_NO_SRP\n    if \(type & SSL_kSRP\) \{",
             "payload": (
                 "    if (type & (SSL_kBDHE)) {\n"
                 "        if(!btls_construct_ske_bign_dhe(s, pkt))\n"
                 "            goto err;\n"
                 "    } else\n"
                 "    if (type & SSL_kBDHEPSK) {\n"
                 "        if(!btls_construct_ske_psk_bign_dhe(s, pkt))\n"
                 "            goto err;\n"
                 "    } else\n")},
        ],
    },
    {
        "id": "statem_srvr.psk_hint",
        "desc": "",
        "file": "ssl/statem/statem_srvr.c",
        "op": "replace",
        "guard": "algorithm_mkey != SSL_kBDHEPSK",
        "conditions": [
            {"when": V3, "anchor": r"    if \(type & SSL_PSK\) \{",
             "payload": ("    if ((type & SSL_PSK) && "
                         "(s->s3.tmp.new_cipher->algorithm_mkey != SSL_kBDHEPSK)) {")},
            {"when": V111, "anchor": r"    if \(type & SSL_PSK\) \{",
             "payload": ("    if ((type & SSL_PSK) && "
                         "(s->s3->tmp.new_cipher->algorithm_mkey != SSL_kBDHEPSK)) {")},
        ],
    },
    {
        "id": "statem_srvr.process_cke",
        "desc": "",
        "file": "ssl/statem/statem_srvr.c",
        "op": "insert_before",
        "anchor": r"    \} else \{\n        SSLfatal\(s, SSL_AD_INTERNAL_ERROR,.*?SSL_R_UNKNOWN_CIPHER_TYPE",
        "guard": "btls_process_cke_bign_dht",
        "payload": (
            "    } else if (alg_k & (SSL_kBDHE | SSL_kBDHEPSK)) {\n"
            "        if (!tls_process_cke_ecdhe(s, pkt)) {\n"
            "            /* SSLfatal() already called */\n"
            "            goto err;\n"
            "        }\n"
            "    } else if (alg_k & (SSL_kBDHT | SSL_kBDHTPSK)) {\n"
            "        if (!btls_process_cke_bign_dht(s, pkt)) {\n"
            "            /* SSLfatal() already called */\n"
            "            goto err;\n"
            "        }\n"),
    },

    # ssl/t1_lib.c
    {
        "id": "t1_lib.include",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "op": "insert_after",
        "anchor": r"#include <openssl/ct\.h>\n",
        "guard": '#include "btls.h"',
        "payload": '#include "btls.h"\n',
    },
    {
        "id": "t1_lib.group_nids",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "op": "replace",
        "guard": "NID_bign_curve256v1, 0xFE01",
        "conditions": [
            {"when": NEW, "anchor": r"    \{ NID_ffdhe8192, OSSL_TLS_GROUP_ID_ffdhe8192 \}\n",
             "payload": ("    { NID_ffdhe8192, OSSL_TLS_GROUP_ID_ffdhe8192 },\n"
                         "    { NID_bign_curve256v1, 0xFE01 }, /* BIGN_CURVE256V1_ID */\n"
                         "    { NID_bign_curve384v1, 0xFE02 }, /* BIGN_CURVE384V1_ID */\n"
                         "    { NID_bign_curve512v1, 0xFE03 }, /* BIGN_CURVE512V1_ID */\n")},
            {"when": OLD3, "anchor": r"    \{NID_ffdhe8192, OSSL_TLS_GROUP_ID_ffdhe8192\}\n",
             "payload": ("    {NID_ffdhe8192, OSSL_TLS_GROUP_ID_ffdhe8192},\n"
                         "    {NID_bign_curve256v1, 0xFE01}, /* BIGN_CURVE256V1_ID */\n"
                         "    {NID_bign_curve384v1, 0xFE02}, /* BIGN_CURVE384V1_ID */\n"
                         "    {NID_bign_curve512v1, 0xFE03}, /* BIGN_CURVE512V1_ID */\n")},
            {"when": V111,
             "anchor": r"    \{EVP_PKEY_X448, 224, TLS_CURVE_CUSTOM\}, /\* X448 \(30\) \*/\n",
             "guard": "NID_bign_curve256v1, 128, TLS_CURVE_CUSTOM",
             "payload": (
                 "    {EVP_PKEY_X448, 224, TLS_CURVE_CUSTOM}, /* X448 (30) */\n"
                 "    {NID_bign_curve256v1, 128, TLS_CURVE_CUSTOM}, /* BIGN_CURVE256V1_ID (31) */\n"
                 "    {NID_bign_curve384v1, 192, TLS_CURVE_CUSTOM}, /* BIGN_CURVE384V1_ID (32) */\n"
                 "    {NID_bign_curve512v1, 256, TLS_CURVE_CUSTOM}, /* BIGN_CURVE512V1_ID (33) */\n")},
        ],
    },
    {
        "id": "t1_lib.default_groups",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "conditions": [
            {"when": NEW, "op": "replace",
             "anchor": r"    \"\?\*X25519MLKEM768 / \?\*X25519:\?secp256r1 / \?X448:\?secp384r1:\?secp521r1"
                       r" / \?ffdhe2048:\?ffdhe3072\"",
             "guard": "?bign-curve256v1",
             "payload": ("    \"?*X25519MLKEM768 / ?*X25519:?secp256r1 / ?X448:?secp384r1:?secp521r1"
                         " / ?ffdhe2048:?ffdhe3072 / ?bign-curve256v1:?bign-curve384v1:?bign-curve512v1\"")},
            {"when": OLD3, "op": "insert_before",
             "anchor": r"^\};\n\nstatic const uint16_t suiteb_curves\[\]",
             "guard": "\t0xFE01,",
             "payload": "\t0xFE01,\n\t0xFE02,\n\t0xFE03\n"},
            {"when": V111, "op": "insert_after",
             "anchor": r"    24,                      /\* secp384r1 \(24\) \*/\n",
             "guard": "/* bign-curve256v1 (31) */",
             "payload": ("    31,                      /* bign-curve256v1 (31) */\n"
                         "    32,                      /* bign-curve384v1 (32) */\n"
                         "    33,                      /* bign-curve512v1 (33) */\n")},
        ],
    },
    {
        "id": "t1_lib.add_provider_groups",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "when": V3,
        "op": "replace",
        "guard": "    } else {\n        ctx->group_list_len++;",
        "conditions": [
            {"when": NEW,
             "anchor": (r"        ctx->group_list_len\+\+;\n        ginf = NULL;\n"
                        r"        EVP_KEYMGMT_free\(keymgmt\);\n    \}\n"),
             "payload": ("        ctx->group_list_len++;\n        ginf = NULL;\n"
                         "        EVP_KEYMGMT_free(keymgmt);\n"
                         "    } else {\n"
                         "        ctx->group_list_len++;\n"
                         "        ginf = NULL;\n"
                         "    }\n")},
            {"when": OLD3,
             "anchor": r"        EVP_KEYMGMT_free\(keymgmt\);\n    \}\n",
             "payload": ("        EVP_KEYMGMT_free(keymgmt);\n"
                         "    } else {\n"
                         "        ctx->group_list_len++;\n"
                         "        ginf = NULL;\n"
                         "    }\n")},
        ],
    },
    {
        "id": "t1_lib.valid_group",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "when": V3,
        "op": "replace",
        "guard": 'ginfo->algorithm, "bign"',
        "conditions": [
            {"when": NEW, "anchor": r"        \|\| strcmp\(ginfo->algorithm, \"X448\"\) == 0;",
             "payload": ("        || strcmp(ginfo->algorithm, \"X448\") == 0\n"
                         "        || strncmp(ginfo->algorithm, \"bign\", 4) == 0;")},
            {"when": OLD3, "anchor": r"           \|\| strcmp\(ginfo->algorithm, \"X448\"\) == 0;",
             "payload": ("           || strcmp(ginfo->algorithm, \"X448\") == 0\n"
                         "           || strcmp(ginfo->algorithm, \"bign\") == 0;")},
        ],
    },
    {
        "id": "t1_lib.tls12_sigalgs",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "op": "replace",
        "anchor": lit("    TLSEXT_SIGALG_gostr34102001_gostr3411,\n#endif\n};\n"),
        "guard": "TLSEXT_SIGALG_bign_sign_128,",
        "payload": (
            "    TLSEXT_SIGALG_gostr34102001_gostr3411,\n"
            "#endif\n"
            "    TLSEXT_SIGALG_bign_sign_128,\n"
            "    TLSEXT_SIGALG_bign_sign_192,\n"
            "    TLSEXT_SIGALG_bign_sign_256,\n"
            "    TLSEXT_SIGALG_bign_with_hbelt,\n"
            "    TLSEXT_SIGALG_bign_with_bash384,\n"
            "    TLSEXT_SIGALG_bign_with_bash512\n"
            "};\n"),
    },
    {
        "id": "t1_lib.sigalg_lookup_comma",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "when": "<3.5",
        "op": "replace",
        "anchor": r"(\n     NID_undef, NID_undef(?:, 1)?)\}\n#endif\n",
        "guard_re": r"\n     NID_undef, NID_undef(?:, 1)?\},\n#endif\n",
        "payload": "$1},\n#endif\n",
    },
    {
        "id": "t1_lib.sigalg_lookup",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "op": "insert_before",
        "anchor": r"^\};\n/\* Legacy sigalgs for TLS < 1\.2 RSA TLS signatures \*/",
        "guard": "SSL_MD_HBELT_IDX",
        "conditions": [
            {"when": NEW, "payload_file": "sigalg_lookup.new.c"},
            {"when": OLD3, "payload_file": "sigalg_lookup.old3.c"},
            {"when": V111, "payload_file": "sigalg_lookup.v111.c"},
        ],
    },
    {
        "id": "t1_lib.set_cert_validity",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "op": "insert_after",
        "anchor": r"    tls1_check_chain\(s, NULL, NULL, NULL, SSL_PKEY_ED448\);\n",
        "guard": "SSL_PKEY_BIGN);",
        "payload": "    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_BIGN);\n",
    },
    {
        "id": "t1_lib.check_cert_usable",
        "desc": "",
        "file": "ssl/t1_lib.c",
        "when": V3,
        "guard": "default_mdnid",
        "conditions": [
            {"when": NEW, "op": "insert_before",
             "anchor": r"    /\*\n     \* If the given EVP_PKEY cannot support signing with this digest,",
             "payload": (
                 "    int default_mdnid = NID_undef;\n"
                 "    ERR_set_mark();\n"
                 "    if (EVP_PKEY_get_default_digest_nid(pkey, &default_mdnid) == 2 &&\n"
                 "        sig->hash != default_mdnid)\n"
                 "            return 0;\n"
                 "    ERR_pop_to_mark();\n")},
            {"when": OLD3, "op": "replace",
             "anchor": lit("    /*\n"
                           "     * If the given EVP_PKEY cannot support signing with this digest,\n"
                           "     * the answer is simply 'no'.\n"
                           "     */\n"),
             "payload": (
                 "    int default_mdnid = NID_undef;\n"
                 "    ERR_set_mark();\n"
                 "    if (EVP_PKEY_get_default_digest_nid(pkey, &default_mdnid) == 2 &&\n"
                 "        sig->hash != default_mdnid)\n"
                 "            return 0;\n"
                 "    ERR_pop_to_mark();\n\n"
                 "    /*\n"
                 "     * If the given EVP_PKEY cannot support signing with this digest,\n"
                 "     * the answer is simply 'no'.\n"
                 "     */\n\n")},
        ],
    },

    # ssl/t1_trce.c

    {
        "id": "t1_trce.ciphers_tbl",
        "desc": "",
        "file": "ssl/t1_trce.c",
        "op": "insert_after",
        "guard": "BDHE-BIGN_WITH-BELT-CTR-MAC-HBELT",
        "conditions": [
            {"when": OLD3, "anchor": r"    \{0xC102, \"GOST2012-GOST8912-IANA\"\},\n",
             "payload": (
                 '    {0xFF15, "BDHE-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF16, "BDHE-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '    {0xFF17, "BDHT-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF18, "BDHT-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '    {0xFF19, "BDHE-PSK-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF1A, "BDHE-PSK-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '    {0xFF1B, "BDHT-PSK-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF1C, "BDHT-PSK-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '\t{0xFF1D, "BELT-CHE256-BELT-HASH"},\n'
                 '\t{0xFF1E, "BASH-PRG_AE256-BASH256"},\n')},
            {"when": NEW, "anchor": r"    \{ 0xC102, \"GOST2012-GOST8912-IANA\" \},\n",
             "payload": (
                 '    { 0xFF15, "BDHE-BIGN_WITH-BELT-CTR-MAC-HBELT" },\n'
                 '    { 0xFF16, "BDHE-BIGN_WITH-BELT-DWP-HBELT" },\n'
                 '    { 0xFF17, "BDHT-BIGN_WITH-BELT-CTR-MAC-HBELT" },\n'
                 '    { 0xFF18, "BDHT-BIGN_WITH-BELT-DWP-HBELT" },\n'
                 '    { 0xFF19, "BDHE-PSK-BIGN_WITH-BELT-CTR-MAC-HBELT" },\n'
                 '    { 0xFF1A, "BDHE-PSK-BIGN_WITH-BELT-DWP-HBELT" },\n'
                 '    { 0xFF1B, "BDHT-PSK-BIGN_WITH-BELT-CTR-MAC-HBELT" },\n'
                 '    { 0xFF1C, "BDHT-PSK-BIGN_WITH-BELT-DWP-HBELT" },\n'
                 '\t{ 0xFF1D, "BELT-CHE256-BELT-HASH" },\n'
                 '\t{ 0xFF1E, "BASH-PRG_AE256-BASH256" },\n')},
            {"when": V111, "anchor": r"    \{0xFF87, \"GOST2012-NULL-GOST12\"\},\n",
             "payload": (
                 '    {0xFF15, "BDHE-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF16, "BDHE-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '    {0xFF17, "BDHT-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF18, "BDHT-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '    {0xFF19, "BDHE-PSK-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF1A, "BDHE-PSK-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '    {0xFF1B, "BDHT-PSK-BIGN_WITH-BELT-CTR-MAC-HBELT"},\n'
                 '    {0xFF1C, "BDHT-PSK-BIGN_WITH-BELT-DWP-HBELT"},\n'
                 '    {0xFF1D, "BELT-CHE256-BELT-HASH"},\n'
                 '    {0xFF1E, "BASH-PRG_AE256-BASH256"},\n')},
        ],
    },
    {
        "id": "t1_trce.groups_tbl",
        "desc": "",
        "file": "ssl/t1_trce.c",
        "when": V111,
        "op": "insert_after",
        "anchor": r"    \{30, \"ecdh_x448\"\},\n",
        "guard": '{31, "bign-curve256v1"}',
        "payload": ('    {31, "bign-curve256v1"},\n'
                    '    {32, "bign-curve384v1"},\n'
                    '    {33, "bign-curve512v1"},\n'),
    },
    {
        "id": "t1_trce.sigalg_tbl",
        "desc": "names of the bign sigalgs in the trace output",
        "file": "ssl/t1_trce.c",
        "guard": "bign_auth128",
        "conditions": [
            {"when": OLD3, "op": "insert_after",
             "anchor": r"    \{TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512,"
                       r" \"ecdsa_brainpoolP512r1_sha512\"\},\n",
             "payload": (
                 '    {TLSEXT_SIGALG_bign_sign_128, "bign_auth128"},\n'
                 '    {TLSEXT_SIGALG_bign_sign_192, "bign_auth192"},\n'
                 '    {TLSEXT_SIGALG_bign_sign_256, "bign_auth256"},\n'
                 '    {TLSEXT_SIGALG_bign_with_hbelt, "bign_with_hbelt"},\n'
                 '    {TLSEXT_SIGALG_bign_with_bash384, "bign_with_bash384"},\n'
                 '    {TLSEXT_SIGALG_bign_with_bash512, "bign_with_bash512"},\n')},
            {"when": NEW, "op": "insert_after",
             "anchor": r"    \{ TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512,"
                       r" TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512_name \},\n",
             "payload": (
                 '    { TLSEXT_SIGALG_bign_sign_128, "bign_auth128" },\n'
                 '    { TLSEXT_SIGALG_bign_sign_192, "bign_auth192" },\n'
                 '    { TLSEXT_SIGALG_bign_sign_256, "bign_auth256" },\n'
                 '    { TLSEXT_SIGALG_bign_with_hbelt, "bign_with_hbelt" },\n'
                 '    { TLSEXT_SIGALG_bign_with_bash384, "bign_with_bash384" },\n'
                 '    { TLSEXT_SIGALG_bign_with_bash512, "bign_with_bash512" },\n')},
            {"when": V111, "op": "insert_after",
             "anchor": r"    \{TLSEXT_SIGALG_gostr34102001_gostr3411, \"gost2001_gost94\"\},\n",
             "payload": (
                 '\t{TLSEXT_SIGALG_bign_sign_128, "bign_auth128"},\n'
                 '\t{TLSEXT_SIGALG_bign_sign_192, "bign_auth192"},\n'
                 '\t{TLSEXT_SIGALG_bign_sign_256, "bign_auth256"},\n'
                 '    {TLSEXT_SIGALG_bign_with_hbelt, "bign_with_hbelt"},\n'
                 '    {TLSEXT_SIGALG_bign_with_bash384, "bign_with_bash384"},\n'
                 '    {TLSEXT_SIGALG_bign_with_bash512, "bign_with_bash512"},\n')},
        ],
    },
    {
        "id": "t1_trce.mldsa_comma",
        "desc": "",
        "file": "ssl/t1_trce.c",
        "when": NEW,
        "op": "replace",
        "anchor": r"    \{ 0x0906, \"mldsa87\" \}\n",
        "guard": '{ 0x0906, "mldsa87" },',
        "payload": "    { 0x0906, \"mldsa87\" },\n",
    },

    # ssl/tls13_enc.c
    {
        "id": "tls13_enc.include",
        "desc": "",
        "file": "ssl/tls13_enc.c",
        "when": V111,
        "op": "insert_after",
        "anchor": r"#include <stdlib\.h>\n",
        "guard": '#include "btls.h"',
        "payload": '#include "btls.h"\n',
    },
    {
        "id": "tls13_enc.algenc_decl",
        "desc": "",
        "file": "ssl/tls13_enc.c",
        "op": "insert_after",
        "conditions": [
            {"when": NEW, "anchor": lit("    size_t hashlen;\n    int mode, mac_mdleni;\n"),
             "guard_re": r"    int mode, mac_mdleni;\n    uint32_t algenc;",
             "payload": "    uint32_t algenc;\n"},
            {"when": OLD3, "anchor": lit("    size_t hashlen;\n    int mode;\n"),
             "guard_re": r"    int mode;\n    uint32_t algenc;",
             "payload": "    uint32_t algenc;\n"},
            {"when": V111,
             "anchor": lit("    int hashleni = EVP_MD_size(md);\n    size_t hashlen;\n"),
             "guard_re": r"    size_t hashlen;\n\tuint32_t algenc;",
             "payload": "\tuint32_t algenc;\n"},
        ],
    },
    {
        "id": "tls13_enc.hoist_algenc",
        "desc": "",
        "file": "ssl/tls13_enc.c",
        "op": "replace",
        "conditions": [
            {"when": NEW, "anchor": lit(HOIST_CCM_NEW), "payload": HOIST_NEW,
             "guard_re": r"if \(mode == EVP_CIPH_CCM_MODE\) \{\n\n            if \(algenc"},
            {"when": OLD3, "anchor": lit(HOIST_CCM_OLD3), "payload": HOIST_OLD3,
             "guard_re": r"if \(mode == EVP_CIPH_CCM_MODE\) \{\n        if \(algenc"},
            {"when": V111, "anchor": lit(HOIST_CCM_V111), "payload": HOIST_V111,
             "guard_re": r"if \(EVP_CIPHER_mode\(ciph\) == EVP_CIPH_CCM_MODE\) \{\n        if \(algenc"},
        ],
    },
    {
        "id": "tls13_enc.taglen",
        "desc": "",
        "file": "ssl/tls13_enc.c",
        "op": "replace",
        "guard": "EVP_BELTCHE_TLS_TAG_LEN",
        "conditions": [
            {"when": NEW,
             "anchor": lit("                *taglen = EVP_GCM_TLS_TAG_LEN;\n"
                           "            } else {\n"),
             "payload": ("                *taglen = EVP_GCM_TLS_TAG_LEN;\n"
                         "            } else if (algenc & SSL_BELTCHE) {\n"
                         "                *taglen = EVP_BELTCHE_TLS_TAG_LEN;\n"
                         "            } else if (algenc & SSL_BASHPRGAE) {\n"
                         "                *taglen = EVP_BASHPRGAE_TLS_TAG_LEN;\n"
                         "            } else {\n")},
            {"when": OLD3,
             "anchor": lit("            *taglen = EVP_GCM_TLS_TAG_LEN;\n"
                           "        } else {\n"),
             "payload": ("            *taglen = EVP_GCM_TLS_TAG_LEN;\n"
                         "        } else if (algenc & SSL_BELTCHE) {\n"
                         "\t\t\t*taglen = EVP_BELTCHE_TLS_TAG_LEN;\n"
                         "\t\t} else if (algenc & SSL_BASHPRGAE) {\n"
                         "\t\t\t*taglen = EVP_BASHPRGAE_TLS_TAG_LEN;\n"
                         "\t\t} else {\n")},
            {"when": V111,
             "anchor": lit("    } else {\n"
                           "        ivlen = EVP_CIPHER_iv_length(ciph);\n"
                           "        taglen = 0;\n"
                           "    }\n"),
             "payload": ("    } else if (algenc & SSL_BELTCHE) {\n"
                         "\t\tivlen = EVP_CIPHER_iv_length(ciph);\n"
                         "\t\ttaglen = EVP_BELTCHE_TLS_TAG_LEN;\n"
                         "\t} else if (algenc & SSL_BASHPRGAE) {\n"
                         "\t\tivlen = EVP_CIPHER_iv_length(ciph);\n"
                         "\t\ttaglen = EVP_BASHPRGAE_TLS_TAG_LEN;\n"
                         "\t} else {\n"
                         "        ivlen = EVP_CIPHER_iv_length(ciph);\n"
                         "        taglen = 0;\n"
                         "    }\n")},
        ],
    },
]
