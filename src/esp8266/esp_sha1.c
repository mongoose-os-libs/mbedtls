/*
 * Copyright (c) 2014-2020 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>

#include "mbedtls/platform_util.h"
#include "mbedtls/sha1.h"

// Decls from wpa_supplicant, implementation in ROM.
void SHA1Init(mbedtls_sha1_context *ctx);
void SHA1Update(mbedtls_sha1_context *ctx, const void *data, uint32_t len);
void SHA1Final(unsigned char digest[20], mbedtls_sha1_context *ctx);

#if defined(MBEDTLS_SHA1_ALT)
void mbedtls_sha1_init(mbedtls_sha1_context *ctx) {
  memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha1_free(mbedtls_sha1_context *ctx) {
  if (ctx == NULL) return;
  mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}

void mbedtls_sha1_clone(mbedtls_sha1_context *dst,
                        const mbedtls_sha1_context *src) {
  *dst = *src;
}

int mbedtls_sha1_starts_ret(mbedtls_sha1_context *ctx) {
  SHA1Init(ctx);
  return 0;
}

int mbedtls_sha1_update_ret(mbedtls_sha1_context *ctx,
                            const unsigned char *input, size_t ilen) {
  SHA1Update(ctx, input, ilen);
  return 0;
}

int mbedtls_internal_sha1_process(mbedtls_sha1_context *ctx,
                                  const unsigned char data[64]) {
  SHA1Update(ctx, data, 64);
  return 0;
}

int mbedtls_sha1_finish_ret(mbedtls_sha1_context *ctx,
                            unsigned char output[16]) {
  SHA1Final(output, ctx);
  return 0;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha1_starts(mbedtls_sha1_context *ctx) {
  mbedtls_sha1_starts_ret(ctx);
}

void mbedtls_sha1_process(mbedtls_sha1_context *ctx,
                          const unsigned char data[64]) {
  mbedtls_internal_sha1_process(ctx, data);
}

void mbedtls_sha1_update(mbedtls_sha1_context *ctx, const unsigned char *input,
                         size_t ilen) {
  mbedtls_sha1_update_ret(ctx, input, ilen);
}

void mbedtls_sha1_finish(mbedtls_sha1_context *ctx, unsigned char output[20]) {
  mbedtls_sha1_finish_ret(ctx, output);
}
#endif  // !defined(MBEDTLS_DEPRECATED_REMOVED)

#endif  // defined(MBEDTLS_SHA1_ALT)
