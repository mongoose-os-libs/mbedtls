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

#include "mbedtls/md5.h"
#include "mbedtls/platform_util.h"

// Decls from wpa_supplicant, implementation in ROM.
extern void MD5Init(mbedtls_md5_context *ctx);
extern void MD5Update(mbedtls_md5_context *ctx, unsigned char const *buf,
                      unsigned len);
extern void MD5Final(unsigned char digest[16], mbedtls_md5_context *ctx);

#if defined(MBEDTLS_MD5_ALT)
void mbedtls_md5_init(mbedtls_md5_context *ctx) {
  memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_md5_free(mbedtls_md5_context *ctx) {
  if (ctx == NULL) return;
  mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}

void mbedtls_md5_clone(mbedtls_md5_context *dst,
                       const mbedtls_md5_context *src) {
  *dst = *src;
}

int mbedtls_md5_starts_ret(mbedtls_md5_context *ctx) {
  MD5Init(ctx);
  return 0;
}

int mbedtls_md5_update_ret(mbedtls_md5_context *ctx, const unsigned char *input,
                           size_t ilen) {
  MD5Update(ctx, input, ilen);
  return 0;
}

int mbedtls_internal_md5_process(mbedtls_md5_context *ctx,
                                 const unsigned char data[64]) {
  MD5Update(ctx, data, 64);
  return 0;
}

int mbedtls_md5_finish_ret(mbedtls_md5_context *ctx, unsigned char output[16]) {
  MD5Final(output, ctx);
  return 0;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_starts(mbedtls_md5_context *ctx) {
  MD5Init(ctx);
}

void mbedtls_md5_update(mbedtls_md5_context *ctx, const unsigned char *input,
                        size_t ilen) {
  mbedtls_md5_update_ret(ctx, input, ilen);
}

void mbedtls_md5_process(mbedtls_md5_context *ctx,
                         const unsigned char data[64]) {
  mbedtls_internal_md5_process(ctx, data);
}

void mbedtls_md5_finish(mbedtls_md5_context *ctx, unsigned char output[16]) {
  mbedtls_md5_finish_ret(ctx, output);
}
#endif  // !defined(MBEDTLS_DEPRECATED_REMOVED)

#endif  // defined(MBEDTLS_MD5_ALT)
