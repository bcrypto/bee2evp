static int fix_bign_ecx(enum state state,
                         const struct translation_st *translation,
                         struct translation_ctx_st *ctx)
{
    switch (state) {
    case PRE_PARAMS_TO_CTRL:
        if (!EVP_PKEY_CTX_IS_GEN_OP(ctx->pctx))
            return 0;
        ctx->ctrl_cmd = EVP_PKEY_ALG_CTRL + 1;
        ctx->p1 = OBJ_sn2nid(ctx->params->data);
        return 1;
    case POST_PARAMS_TO_CTRL:
        ctx->p1 = 1;
        return 1;
    default:
        return 0;
    }
}

