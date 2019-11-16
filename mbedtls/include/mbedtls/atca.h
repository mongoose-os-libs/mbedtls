/*
 * Copyright (c) 2014-2019 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MBEDTLS_ATCA_H
#define MBEDTLS_ATCA_H

#include <stdint.h>

#define MBEDTLS_ATCA_SLOT_INVALID 0xff
#define MBEDTLS_ATCA_SLOT_TEMPKEY 0x10
#define MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX "ATCA:"
#define MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX_LEN (sizeof(MBEDTLS_ATCA_KEY_FILE_NAME_PREFIX) - 1)

#ifdef __cplusplus
extern "C" {
#endif

/* Try to claim tempkey for ECDH, if not currently claimed.
 * Returns true if claimed.
 * If claimed, must be released later. */
int ecp_atca_try_claim_tempkey(void);
void ecp_atca_release_tempkey(void);

/* Provided externally, returns 1 if the chip is available (via basic API). */
extern int mbedtls_atca_is_available(void);

/* Provided externally and returns a bitmask of slots available for ECDH:
 * bit #N = 1 -> slot N available for ECDH. Only slots 0-7 can be used for
 * ECC key operations, so 8 bits is enough. */
extern uint16_t mbedtls_atca_get_ecdh_slots_mask(void);

/* Provided externally, returns true if chip is ATECC608A. */
extern int mbedtls_atca_is_608(void);

#ifdef __cplusplus
}
#endif

#endif /* atca.h */
