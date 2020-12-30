/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECP_ATCA)

#include "mbedtls/ecp_atca.h"

#include <string.h>

#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/platform.h"

#include "cryptoauthlib.h"

/*
 * Whether a new ECDH key should be generated.
 * ATECC508 guarantees 400K write cycles per slot. If we generate a new ECDH key
 * every time every 10 seconds (not incinceivable if connectin is dropped and
 * retried), that's only ~45 days before we can expect it to wear out.
 * Instead, we generate new keys with about 1.6% probability. With 1 slot that's
 * 8 years, which should be plenty.
 */
#define SHOULD_REGEN(rnd) (((rnd) >> 2) == 42)

static uint8_t s_tempkey_is_busy = 0;

int ecp_atca_try_claim_tempkey(void)
{
    if ( s_tempkey_is_busy ) return 0;
    s_tempkey_is_busy = 1;
    return 1;
}

void ecp_atca_release_tempkey(void)
{
    s_tempkey_is_busy = 0;
}

/* NB: ATECC508 only supports P256 curve. */
static size_t eckey_atca_get_bitlen( const void *ctx ) {
  (void) ctx;
  return 256;
}

static int eckey_atca_can_do( mbedtls_pk_type_t type )
{
  /* TODO(rojer): Should verify slot settings. */
    return( type == MBEDTLS_PK_ECKEY ||
            type == MBEDTLS_PK_ECKEY_DH ||
            type == MBEDTLS_PK_ECDSA );
}

int eckey_atca_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
  fprintf(stderr, "ATCA eckey_verify: NOT IMPLEMENTED\n");
  /* This function is not actually used during handshake. */
  (void) ctx;
  (void) md_alg;
  (void) hash;
  (void) hash_len;
  (void) sig;
  (void) sig_len;
  return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
}

int eckey_atca_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig_der, size_t *sig_der_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
  int ret;
  mbedtls_mpi r, s;
  ATCA_STATUS status;
  uint8_t raw_sig[ATCA_SIG_SIZE];
  int slot = ((intptr_t) ctx) - 1;

  /* Can only sign 256-bit digests. */
  if (hash_len != 32) {
    fprintf(stderr, "ATCA:%d ECDSA sign failed: expected 32 bytes to sign, got %d\n", slot, (int) hash_len);
    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
  }
  if ((status = atcab_sign(slot, hash, raw_sig)) != ATCA_SUCCESS) {
    fprintf(stderr, "ATCA:%d ECDSA sign failed: 0x%02x\n", slot, status);
    return MBEDTLS_ERR_ECP_SIGN_FAILED;
  }

  mbedtls_mpi_init( &r );
  mbedtls_mpi_init( &s );
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&r, raw_sig, ATCA_SIG_SIZE / 2));
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&s, raw_sig + ATCA_SIG_SIZE / 2, ATCA_SIG_SIZE / 2));
  MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig_der, sig_der_len));
  mbedtls_mpi_free( &r );
  mbedtls_mpi_free( &s );
  fprintf(stderr, "ATCA:%d ECDSA sign ok\n", slot);
  return 0;

cleanup:
  (void) ret;
  (void) md_alg;
  (void) f_rng;
  (void) p_rng;
  return MBEDTLS_ERR_ECP_SIGN_FAILED;
}

static int eckey_atca_check_pair( const void *pub, const void *prv )
{
  /* TODO(rojer) */
  (void) pub;
  (void) prv;
  fprintf(stderr, "ATCA check pair: NOT IMPLEMENTED\n");
  return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
}

static void *eckey_atca_alloc_wrap( void )
{
  if (!mbedtls_atca_is_available()) return NULL;
  /* Can't return NULL, it's interpreted as an error! */
  return (void *) 1;
}

static void eckey_atca_free_wrap( void *ctx )
{
  (void) ctx;
}

static void eckey_atca_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
  /* TODO(rojer) */
  items->type = MBEDTLS_PK_DEBUG_NONE;
  (void) ctx;
}

const mbedtls_pk_info_t mbedtls_eckey_atca_info = {
    MBEDTLS_PK_ECKEY,
    MBEDTLS_ECP_ATCA_KEY_NAME,
    eckey_atca_get_bitlen,
    eckey_atca_can_do,
    eckey_atca_verify_wrap,
    eckey_atca_sign_wrap,
    NULL,
    NULL,
    eckey_atca_check_pair,
    eckey_atca_alloc_wrap,
    eckey_atca_free_wrap,
    eckey_atca_debug,
};

int ecdsa_atca_verify(mbedtls_ecdsa_context *ctx,
                      const unsigned char *hash, size_t hlen,
                      const mbedtls_mpi *r, const mbedtls_mpi *s) {
  ATCA_STATUS status;
  bool verified = false;
  uint8_t raw_pubkey[ATCA_PUB_KEY_SIZE], raw_sig[ATCA_SIG_SIZE];
  if (!mbedtls_atca_is_available() ||
      ctx->grp.id != MBEDTLS_ECP_DP_SECP256R1 || hlen != 32) {
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
  }
  mbedtls_mpi_write_binary(&ctx->Q.X, raw_pubkey, ATCA_PUB_KEY_SIZE / 2);
  mbedtls_mpi_write_binary(&ctx->Q.Y, raw_pubkey + ATCA_PUB_KEY_SIZE / 2, ATCA_PUB_KEY_SIZE / 2);
  mbedtls_mpi_write_binary(r, raw_sig, ATCA_SIG_SIZE / 2);
  mbedtls_mpi_write_binary(s, raw_sig + ATCA_SIG_SIZE / 2, ATCA_SIG_SIZE / 2);
  status = atcab_verify_extern(hash, raw_sig, raw_pubkey, &verified);
  if (status != ATCA_SUCCESS) {
    fprintf(stderr, "ATCA ECDSA verify failed: 0x%02x\n", status);
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
  }
  fprintf(stderr, "ATCA ECDSA verify ok, %sverified\n", (verified ? "" : "NOT "));
  return (verified ? 0 : MBEDTLS_ERR_ECP_VERIFY_FAILED);
}

static int get_ecdh_slot(uint8_t available_slots, uint8_t rnd)
{
    int slot, t, num_av_slots, step;
    for (num_av_slots = 0, t = available_slots; t != 0; t >>= 1)
    {
        if (t & 1) num_av_slots++;
    }
    if ( num_av_slots == 0 ) return MBEDTLS_ATCA_SLOT_INVALID;
    step = 256 / num_av_slots;
    for ( t = 0, slot = 0; available_slots != 0; )
    {
        if ( available_slots & 1 )
        {
            t += step;
            if (t > rnd) break;
        }
        if ( ( available_slots >>= 1 ) != 0 ) slot++;
    }
    return slot;
}

static int ecp_atca_ecdh_gen_keypair_slot( mbedtls_ecp_point *Q, uint8_t slot, int rnd )
{
    int ret;
    ATCA_STATUS status;
    uint8_t raw_pubkey[ATCA_PUB_KEY_SIZE];
    int gen = ( slot == MBEDTLS_ATCA_SLOT_TEMPKEY ? 1 : SHOULD_REGEN(rnd) );
    do
    {
        uint16_t real_slot = ( slot == MBEDTLS_ATCA_SLOT_TEMPKEY ? 0xffff : slot );
        status = ( gen ? atcab_genkey( real_slot, raw_pubkey ) :
                         atcab_get_pubkey( real_slot, raw_pubkey ) );
        if (status != ATCA_SUCCESS)
        {
            fprintf( stderr, "ATCA:%d failed to %s ECDH pubkey: 0x%02x\n",
                     slot, (gen ? "gen" : "get"), status );
            if ( !gen && status == ATCA_EXECUTION_ERROR )
            {
                /* It may be that this slot has never had a key generated. Try it. */
                gen = 1;
            }
            else
            {
                return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
            }
        }
    } while ( status != ATCA_SUCCESS );
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Q->X, raw_pubkey, ATCA_PUB_KEY_SIZE / 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Q->Y, raw_pubkey + ATCA_PUB_KEY_SIZE / 2, ATCA_PUB_KEY_SIZE / 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&Q->Z, 1));
    fprintf(stderr, "ATCA:%d ECDH %s pubkey ok\n", slot, (gen ? "gen" : "get"));
    return 0;

cleanup:
  (void) ret;
  return -1;
}

int ecp_atca_ecdh_gen_keypair(mbedtls_ecp_point *Q, uint8_t *slot,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret;
    int rnd = 0;
    if (!mbedtls_atca_is_available() )
    {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    /* Try tempkey if possible and available (not used by other connection). */
    if ( mbedtls_atca_is_608() && ecp_atca_try_claim_tempkey() )
    {
        ret = ecp_atca_ecdh_gen_keypair_slot( Q, MBEDTLS_ATCA_SLOT_TEMPKEY, 0 );
        if ( ret == 0 )
        {
            *slot = MBEDTLS_ATCA_SLOT_TEMPKEY;
            return ( 0 );
        }
        ecp_atca_release_tempkey();
    }
    /* Fall back to using persistent slots. */
    if ( f_rng(p_rng, (uint8_t *) &rnd, sizeof(rnd)) != 0 )
    {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    *slot = get_ecdh_slot(mbedtls_atca_get_ecdh_slots_mask(), rnd);
    if ( *slot == MBEDTLS_ATCA_SLOT_INVALID )
    {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
    return ecp_atca_ecdh_gen_keypair_slot( Q, *slot, rnd );
}

int ecp_atca_ecdh_compute_pms(uint8_t slot, mbedtls_ecp_point *Qp, mbedtls_mpi *z)
{
    int ret;
    uint8_t mode;
    ATCA_STATUS status;
    uint8_t raw_pubkey[ATCA_PUB_KEY_SIZE], pms[ATCA_KEY_SIZE];
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &Qp->X, raw_pubkey, ATCA_PUB_KEY_SIZE / 2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &Qp->Y, raw_pubkey + ATCA_PUB_KEY_SIZE / 2, ATCA_PUB_KEY_SIZE / 2 ) );
    mode = ECDH_MODE_COPY_OUTPUT_BUFFER | ECDH_MODE_OUTPUT_CLEAR;
    if ( slot == MBEDTLS_ATCA_SLOT_TEMPKEY )
    {
        mode |= ECDH_MODE_SOURCE_TEMPKEY;
    }
    if ( ( status = atcab_ecdh_base( mode, slot, raw_pubkey, pms, NULL ) ) != ATCA_SUCCESS )
    {
        fprintf( stderr, "ATCA:%d ECDH failed: 0x%02x\n", slot, status );
        return -1;
    }
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( z, pms, ATCA_KEY_SIZE ) );
    fprintf( stderr, "ATCA:%d ECDH ok\n", slot );
    return 0;
cleanup:
    (void) ret;
    return -1;
}

#endif /* MBEDTLS_ECP_ATCA */
