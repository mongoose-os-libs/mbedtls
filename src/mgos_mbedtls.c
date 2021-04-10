/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#include <stdbool.h>

#include "mongoose.h"

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

bool mgos_mbedtls_init(void) {
  return true;
}
