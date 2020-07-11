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

#pragma once

// From wpa_supplicant - ROM crypto comes from there.
typedef struct mbedtls_sha1_context {
  uint32_t state[5];
  uint32_t count[2];
  unsigned char buffer[64];
} mbedtls_sha1_context;
