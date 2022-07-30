/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#pragma once

// TODO(rojer): Enable hardware crypto acceleration.
//#define MBEDTLS_AES_ALT
//#define MBEDTLS_MPI_MUL_MPI_ALT
//#define MBEDTLS_MPI_EXP_MOD_ALT

#define MBEDTLS_CIPHER_MODE_XTS

/* no_extern_c_check */
