/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MBEDTLS_ECP_ATCA_H
#define MBEDTLS_ECP_ATCA_H

#if defined(MBEDTLS_ECP_ATCA)

#include "mbedtls/atca.h"
#include "mbedtls/bignum.h"
#include "mbedtls/pk_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ECP_ATCA_KEY_NAME "EC(ATCA)"
extern const mbedtls_pk_info_t mbedtls_eckey_atca_info;

int ecdsa_atca_verify(mbedtls_ecdsa_context *ctx,
                      const unsigned char *hash, size_t hlen,
                      const mbedtls_mpi *r, const mbedtls_mpi *s);

int ecp_atca_ecdh_gen_keypair(mbedtls_ecp_point *Q, uint8_t *slot,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
int ecp_atca_ecdh_compute_pms(uint8_t slot, mbedtls_ecp_point *Qp, mbedtls_mpi *z);

#ifdef __cplusplus
}
#endif

#endif /* defined(MBEDTLS_ECP_ATCA) */

#endif /* ecp_atca.h */
