/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#include <stdbool.h>

#include "mongoose.h"

#include "mbedtls/entropy_poll.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"

/* Crypto functions for Mongoose. */
void mg_hash_md5_v(size_t num_msgs, const uint8_t *msgs[],
                   const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  mbedtls_md5_context ctx;
  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts_ret(&ctx);
  for (i = 0; i < num_msgs; i++) {
    mbedtls_md5_update_ret(&ctx, msgs[i], msg_lens[i]);
  }
  mbedtls_md5_finish_ret(&ctx, digest);
  mbedtls_md5_free(&ctx);
}

void mg_hash_sha1_v(size_t num_msgs, const uint8_t *msgs[],
                    const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  mbedtls_sha1_context ctx;
  mbedtls_sha1_init(&ctx);
  mbedtls_sha1_starts_ret(&ctx);
  for (i = 0; i < num_msgs; i++) {
    mbedtls_sha1_update_ret(&ctx, msgs[i], msg_lens[i]);
  }
  mbedtls_sha1_finish_ret(&ctx, digest);
  mbedtls_sha1_free(&ctx);
}

void mg_hash_sha256_v(size_t num_msgs, const uint8_t *msgs[],
                      const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, false /* is224 */);
  for (i = 0; i < num_msgs; i++) {
    mbedtls_sha256_update_ret(&ctx, msgs[i], msg_lens[i]);
  }
  mbedtls_sha256_finish_ret(&ctx, digest);
  mbedtls_sha256_free(&ctx);
}

/* This function is provided by platforms */
extern int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len);

/* This feeds the entropy pool (mbedtls_entropy_*). */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
                          size_t *olen) {
  mg_ssl_if_mbed_random(NULL, output, len);
  *olen = len;
  (void) data;
  return 0;
}

bool mgos_mbedtls_init(void) {
  return true;
}
