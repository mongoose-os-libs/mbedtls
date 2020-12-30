// vim: tabstop=4 expandtab shiftwidth=4 ai cin smarttab
/*
 * Copyright (c) 2014-2019 Cesanta Software Limited
 * All rights reserved
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_AES_ATCA)

#include <string.h>

#include "mbedtls/atca.h"
#include "mbedtls/cipher_internal.h"
#include "mbedtls/platform.h"

#include "cryptoauthlib.h"

struct atca_aes_ctx {
    uint8_t key_slot;
    uint8_t key_block;
};

static int atca_aes_crypt_ecb( void *vctx, mbedtls_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    ATCA_STATUS status;
    struct atca_aes_ctx *ctx = (struct atca_aes_ctx *) vctx;
    if( !mbedtls_atca_is_608() )
        return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
    if( ctx->key_slot == MBEDTLS_ATCA_SLOT_INVALID )
        return( MBEDTLS_ERR_CIPHER_INVALID_CONTEXT );
    uint16_t real_slot = ( ctx->key_slot == MBEDTLS_ATCA_SLOT_TEMPKEY ? 0xffff : ctx->key_slot );
    switch( operation )
    {
        case MBEDTLS_ENCRYPT:
            status = atcab_aes_encrypt(real_slot, ctx->key_block, input, output);
            break;
        case MBEDTLS_DECRYPT:
            status = atcab_aes_decrypt(real_slot, ctx->key_block, input, output);
            break;
        default:
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }
    return( status == ATCA_SUCCESS ? 0 : MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED );
}

/*
 * Key is a string, supported formats:
 *   slot
 *   slot.block
 *   ATCA:slot
 *   ATCA:slot.block
 * E.g.: 0 (same as 0.0), 1.2 or ATCA:1.2
 */
static int atca_aes_setkey( void *vctx, const unsigned char *key,
        unsigned int key_bitlen )
{
    char slot[5] = { 0 };
    struct atca_aes_ctx *ctx = (struct atca_aes_ctx *) vctx;
    if( !mbedtls_atca_is_608() )
        return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
    size_t key_len = strlen( ( const char *) key );
    if( key_len > MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX_LEN &&
            memcmp( key, MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX, MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX_LEN ) == 0 )
    {
        key += MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX_LEN;
        key_len -= MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX_LEN;
    }
    if( key_len > 4 )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    const char *delim = strchr( (const char *) key, '.' );
    size_t slot_len = ( delim ? (size_t) ( delim - (const char *) key ) : key_len );
    memcpy( slot, key, slot_len );
    int key_slot = atoi( slot );
    if( ( key_slot < 0 || key_slot > 15 ) && key_slot != MBEDTLS_ATCA_SLOT_TEMPKEY )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    ctx->key_slot = (uint8_t) key_slot;
    if( key_len > slot_len )
    {
        int key_block = atoi( (const char *) ( key + slot_len + 1 ) );
        if( key_block < 0 || key_block > 3 )
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        ctx->key_block = (uint8_t) key_block;
    }
    ( void ) key_bitlen;
    return( 0 );
}

static void * atca_aes_ctx_alloc( void )
{
    struct atca_aes_ctx *ctx = mbedtls_calloc( 1, sizeof( *ctx ) );
    ctx->key_slot = MBEDTLS_ATCA_SLOT_INVALID;
    ctx->key_block = 0;
    return ctx;
}

static void atca_aes_ctx_free( void *ctx )
{
    mbedtls_free( ctx );
}

const mbedtls_cipher_base_t atca_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    atca_aes_crypt_ecb,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    atca_aes_setkey,
    atca_aes_setkey,
    atca_aes_ctx_alloc,
    atca_aes_ctx_free,
};

const mbedtls_cipher_info_t atca_aes_128_ecb_info = {
    MBEDTLS_CIPHER_AES_128_ECB_ATCA,
    MBEDTLS_MODE_ECB,
    128,
    "AES-128-ECB-ATCA",
    0,
    0,
    16,
    &atca_aes_info
};

#endif /* MBEDTLS_AES_ATCA */
