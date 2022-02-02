/*
 * Copyright (c) 2022 Deomid "rojer" Ryabkov
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#include "mgos.h"
#include "mgos_mongoose.h"

#if MG_ENABLE_SSL && MG_SSL_IF == MG_SSL_IF_MBEDTLS_MGOS

#include "mbedtls/debug.h"
#include "mbedtls/ecp.h"
#include "mbedtls/net.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/version.h"
#include "mbedtls/x509_crt.h"

#ifndef MG_TCP_IO_SIZE
#define MG_TCP_IO_SIZE 1460
#endif

#define MG_SET_PTRPTR(_ptr, _v) \
  do {                          \
    if (_ptr) *(_ptr) = _v;     \
  } while (0)

static void mg_ssl_mbed_log(void *ctx, int level, const char *file UNUSED_ARG,
                            int line UNUSED_ARG, const char *str) {
  enum cs_log_level cs_level;
  switch (level) {
    case 1:
      cs_level = LL_ERROR;
      break;
    case 2:
      cs_level = LL_INFO;
      break;
    case 3:
      cs_level = LL_DEBUG;
      break;
    default:
      cs_level = LL_VERBOSE_DEBUG;
  }
  /* mbedTLS passes strings with \n at the end, strip it. */
  LOG(cs_level, ("%p %.*s", ctx, (int) (strlen(str) - 1), str));
  (void) cs_level;
  (void) ctx;
  (void) str;
}

enum mgos_ssl_if_mbed_hs_state {
  MGOS_SSL_IF_MBED_HS_STATE_IDLE = 0,
  MGOS_SSL_IF_MBED_HS_STATE_PENDING = 1,
  MGOS_SSL_IF_MBED_HS_STATE_DONE = 2,
};

struct mg_ssl_if_ctx {
  mbedtls_ssl_config *conf;
  mbedtls_ssl_context *ssl;
  mbedtls_x509_crt *cert;
  mbedtls_pk_context *key;
#ifdef MBEDTLS_X509_CA_CHAIN_ON_DISK
  char *ca_chain_file;
#else
  mbedtls_x509_crt *ca_cert;
#endif
  struct mbuf cipher_suites;
  size_t saved_len;

  enum mgos_ssl_if_mbed_hs_state hs_state;
  int hs_result;
  struct mbuf hs_recv_mbuf;
};

/* Must be provided by the platform. ctx is struct mg_connection. */
extern int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len);

static int mgos_ssl_if_mbed_send_hs(void *arg, const unsigned char *buf,
                                    size_t len) {
  struct mg_connection *nc = arg;
  assert(!(nc->flags & MG_F_SSL_HANDSHAKE_DONE));
  mbuf_append(&nc->send_mbuf, buf, len);
  DBG(("%p SSL HS -> %u", nc, (unsigned) len));
  return len;
}

static int mgos_ssl_if_mbed_recv_hs(void *arg, unsigned char *buf, size_t len) {
  struct mg_connection *nc = arg;
  assert(!(nc->flags & MG_F_SSL_HANDSHAKE_DONE));
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  size_t n = ctx->hs_recv_mbuf.len;
  if (n == 0) return MBEDTLS_ERR_SSL_WANT_READ;
  if (n > len) n = len;
  DBG(("%p SSL HS <- %u", nc, (unsigned) n));
  memcpy(buf, ctx->hs_recv_mbuf.buf, n);
  mbuf_remove(&ctx->hs_recv_mbuf, n);
  mbuf_trim(&ctx->hs_recv_mbuf);
  return n;
}

static int mgos_ssl_if_mbed_send(void *arg, const unsigned char *buf,
                                 size_t len) {
  struct mg_connection *nc = arg;
  assert(nc->flags & MG_F_SSL_HANDSHAKE_DONE);
  int n = nc->iface->vtable->tcp_send(nc, buf, len);
  if (n > 0) return n;
  if (n == 0) return MBEDTLS_ERR_SSL_WANT_WRITE;
  return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int mgos_ssl_if_mbed_recv(void *arg, unsigned char *buf, size_t len) {
  struct mg_connection *nc = arg;
  assert(nc->flags & MG_F_SSL_HANDSHAKE_DONE);
  int n = nc->iface->vtable->tcp_recv(nc, buf, len);
  if (n > 0) return n;
  if (n == 0) return MBEDTLS_ERR_SSL_WANT_READ;
  return MBEDTLS_ERR_NET_RECV_FAILED;
}

void mg_ssl_if_init(void) {
  LOG(LL_INFO, ("%s", MBEDTLS_VERSION_STRING_FULL));
}

enum mg_ssl_if_result mg_ssl_if_conn_accept(struct mg_connection *nc,
                                            struct mg_connection *lc) {
  struct mg_ssl_if_ctx *ctx = calloc(1, sizeof(*ctx));
  struct mg_ssl_if_ctx *lc_ctx = lc->ssl_if_data;
  nc->ssl_if_data = ctx;
  if (ctx == NULL || lc_ctx == NULL) return MG_SSL_ERROR;
  ctx->ssl = calloc(1, sizeof(*ctx->ssl));
  if (mbedtls_ssl_setup(ctx->ssl, lc_ctx->conf) != 0) {
    return MG_SSL_ERROR;
  }
  mbedtls_ssl_set_bio(ctx->ssl, nc, mgos_ssl_if_mbed_send_hs,
                      mgos_ssl_if_mbed_recv_hs, NULL);
  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_use_cert(struct mg_ssl_if_ctx *ctx,
                                         const char *cert, const char *key,
                                         const char **err_msg);
static enum mg_ssl_if_result mg_use_ca_cert(struct mg_ssl_if_ctx *ctx,
                                            const char *cert);
static enum mg_ssl_if_result mg_set_cipher_list(struct mg_ssl_if_ctx *ctx,
                                                const char *ciphers);
#ifdef MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
static enum mg_ssl_if_result mg_ssl_if_mbed_set_psk(struct mg_ssl_if_ctx *ctx,
                                                    const char *identity,
                                                    const char *key);
#endif

enum mg_ssl_if_result mg_ssl_if_conn_init(
    struct mg_connection *nc, const struct mg_ssl_if_conn_params *params,
    const char **err_msg) {
  struct mg_ssl_if_ctx *ctx = calloc(1, sizeof(*ctx));
  DBG(("%p %s,%s,%s", nc, (params->cert ? params->cert : ""),
       (params->key ? params->key : ""),
       (params->ca_cert ? params->ca_cert : "")));

  if (ctx == NULL) {
    MG_SET_PTRPTR(err_msg, "Out of memory");
    return MG_SSL_ERROR;
  }
  nc->ssl_if_data = ctx;
  ctx->conf = (mbedtls_ssl_config *) calloc(1, sizeof(*ctx->conf));
  mbuf_init(&ctx->cipher_suites, 0);
  mbuf_init(&ctx->hs_recv_mbuf, 0);
  mbedtls_ssl_config_init(ctx->conf);
  mbedtls_ssl_conf_dbg(ctx->conf, mg_ssl_mbed_log, nc);
  if (mbedtls_ssl_config_defaults(
          ctx->conf,
          (nc->flags & MG_F_LISTENING ? MBEDTLS_SSL_IS_SERVER
                                      : MBEDTLS_SSL_IS_CLIENT),
          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    MG_SET_PTRPTR(err_msg, "Failed to init SSL config");
    return MG_SSL_ERROR;
  }

  /* TLS 1.2 and up */
  mbedtls_ssl_conf_min_version(ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                               MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_rng(ctx->conf, mg_ssl_if_mbed_random, nc);

  if (params->cert != NULL &&
      mg_use_cert(ctx, params->cert, params->key, err_msg) != MG_SSL_OK) {
    return MG_SSL_ERROR;
  }

  if (params->ca_cert != NULL &&
      mg_use_ca_cert(ctx, params->ca_cert) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL CA cert");
    return MG_SSL_ERROR;
  }

  if (mg_set_cipher_list(ctx, params->cipher_suites) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid cipher suite list");
    return MG_SSL_ERROR;
  }

#ifdef MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
  if (mg_ssl_if_mbed_set_psk(ctx, params->psk_identity, params->psk_key) !=
      MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid PSK settings");
    return MG_SSL_ERROR;
  }
#endif

  if (!(nc->flags & MG_F_LISTENING)) {
    ctx->ssl = (mbedtls_ssl_context *) calloc(1, sizeof(*ctx->ssl));
    mbedtls_ssl_init(ctx->ssl);
    if (mbedtls_ssl_setup(ctx->ssl, ctx->conf) != 0) {
      MG_SET_PTRPTR(err_msg, "Failed to create SSL session");
      return MG_SSL_ERROR;
    }
    if (params->server_name != NULL &&
        mbedtls_ssl_set_hostname(ctx->ssl, params->server_name) != 0) {
      return MG_SSL_ERROR;
    }
    mbedtls_ssl_set_bio(ctx->ssl, nc, mgos_ssl_if_mbed_send_hs,
                        mgos_ssl_if_mbed_recv_hs, NULL);
  }

#ifdef MG_SSL_IF_MBEDTLS_MAX_FRAG_LEN
  if (mbedtls_ssl_conf_max_frag_len(ctx->conf,
#if MG_SSL_IF_MBEDTLS_MAX_FRAG_LEN == 512
                                    MBEDTLS_SSL_MAX_FRAG_LEN_512
#elif MG_SSL_IF_MBEDTLS_MAX_FRAG_LEN == 1024
                                    MBEDTLS_SSL_MAX_FRAG_LEN_1024
#elif MG_SSL_IF_MBEDTLS_MAX_FRAG_LEN == 2048
                                    MBEDTLS_SSL_MAX_FRAG_LEN_2048
#elif MG_SSL_IF_MBEDTLS_MAX_FRAG_LEN == 4096
                                    MBEDTLS_SSL_MAX_FRAG_LEN_4096
#else
#error Invalid MG_SSL_IF_MBEDTLS_MAX_FRAG_LEN
#endif
                                    ) != 0) {
    return MG_SSL_ERROR;
  }
#endif

  nc->flags |= MG_F_SSL;

  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_ssl_if_mbed_err(struct mg_connection *nc,
                                                int ret) {
  enum mg_ssl_if_result res = MG_SSL_OK;
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
    res = MG_SSL_WANT_READ;
  } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    res = MG_SSL_WANT_WRITE;
  } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    LOG(LL_DEBUG, ("%p TLS connection closed by peer", nc));
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    res = MG_SSL_OK;
  } else {
    LOG(LL_ERROR, ("%p mbedTLS error: -0x%04x", nc, -ret));
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    res = MG_SSL_ERROR;
  }
  nc->err = ret;
  return res;
}

static void mg_ssl_if_mbed_free_certs_and_keys(struct mg_ssl_if_ctx *ctx) {
  if (ctx->cert != NULL) {
    mbedtls_x509_crt_free(ctx->cert);
    free(ctx->cert);
    ctx->cert = NULL;
    mbedtls_pk_free(ctx->key);
    free(ctx->key);
    ctx->key = NULL;
  }
#ifdef MBEDTLS_X509_CA_CHAIN_ON_DISK
  free(ctx->ca_chain_file);
  ctx->ca_chain_file = NULL;
#else
  if (ctx->ca_cert != NULL) {
    mbedtls_ssl_conf_ca_chain(ctx->conf, NULL, NULL);
    mbedtls_x509_crt_free(ctx->ca_cert);
    free(ctx->ca_cert);
    ctx->ca_cert = NULL;
  }
#endif
}

static enum mg_ssl_if_result mg_ssl_if_handshake_common(
    struct mg_connection *nc, int res) {
  if (res != 0) return mg_ssl_if_mbed_err(nc, res);
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  // Handshake complete, can run directly from now on.
  mbedtls_ssl_set_bio(ctx->ssl, nc, mgos_ssl_if_mbed_send,
                      mgos_ssl_if_mbed_recv, NULL);
#ifdef MG_SSL_IF_MBEDTLS_FREE_CERTS
  /*
   * Free the peer certificate, we don't need it after handshake.
   * Note that this effectively disables renegotiation.
   */
  mbedtls_x509_crt_free(ctx->ssl->session->peer_cert);
  mbedtls_free(ctx->ssl->session->peer_cert);
  ctx->ssl->session->peer_cert = NULL;
  /* On a client connection we can also free our own and CA certs. */
  if (nc->listener == NULL) {
    if (ctx->conf->key_cert != NULL) {
      /* Note that this assumes one key_cert entry, which matches our init. */
      free(ctx->conf->key_cert);
      ctx->conf->key_cert = NULL;
    }
    mbedtls_ssl_conf_ca_chain(ctx->conf, NULL, NULL);
    mg_ssl_if_mbed_free_certs_and_keys(ctx);
  }
#endif
  return MG_SSL_OK;
}

static void mgos_ssl_if_mbed_handshake_post(void *arg);

static void mgos_ssl_if_mbed_handshake(void *arg) {
  struct mg_connection *nc = arg;
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  ctx->hs_result = mbedtls_ssl_handshake(ctx->ssl);
  mgos_invoke_cb(mgos_ssl_if_mbed_handshake_post, nc, 0);
}

static void mgos_ssl_if_mbed_handshake_post(void *arg) {
  struct mg_connection *nc = arg;
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  DBG(("%p mbedtls_ssl_handshake() -> %d", nc, ctx->hs_result));
  ctx->hs_state = MGOS_SSL_IF_MBED_HS_STATE_DONE;
  mg_if_can_send_cb(nc);  // Trigger connection reprocessing.
}

static void move_or_append_mbuf(struct mbuf *from, struct mbuf *to) {
  if (from->len == 0) return;
  if (to->len == 0) {
    mbuf_move(from, to);
  } else {
    mbuf_append(to, from->buf, from->len);
    mbuf_clear(from);
  }
}

static enum mg_ssl_if_result send_some(struct mg_connection *nc) {
  if (nc->send_mbuf.len == 0) return MG_SSL_WANT_READ;
  int n = nc->send_mbuf.len;
  if (n > MG_TCP_IO_SIZE) n = MG_TCP_IO_SIZE;
  n = nc->iface->vtable->tcp_send(nc, nc->send_mbuf.buf, n);
  if (n > 0) mbuf_remove(&nc->send_mbuf, n);
  mbuf_trim(&nc->send_mbuf);
  return (nc->send_mbuf.len > 0 ? MG_SSL_WANT_WRITE : MG_SSL_WANT_READ);
}

enum mg_ssl_if_result mg_ssl_if_handshake(struct mg_connection *nc) {
  assert(!(nc->flags & MG_F_SSL_HANDSHAKE_DONE));
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  DBG(("mg_ssl_if_handshake %d %d %d %d", (int) ctx->hs_state, ctx->hs_result,
       (int) nc->send_mbuf.len, (int) nc->recv_mbuf.len));
  switch (ctx->hs_state) {
    case MGOS_SSL_IF_MBED_HS_STATE_IDLE:
      // mbedTLS will always consume all of the data, wait for it to happen,
      // don't buffer too much.
      if (nc->recv_mbuf.len == 0) {
        if (nc->recv_mbuf.size < MG_TCP_IO_SIZE) {
          mbuf_resize(&nc->recv_mbuf, MG_TCP_IO_SIZE);
        }
        int n = nc->iface->vtable->tcp_recv(nc, nc->recv_mbuf.buf,
                                            nc->recv_mbuf.size);
        if (n > 0) {
          nc->recv_mbuf.len += n;
        } else if (n < 0) {
          nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        }
      }
      if (ctx->hs_result == MBEDTLS_ERR_SSL_WANT_WRITE ||
          (ctx->hs_result == MBEDTLS_ERR_SSL_WANT_READ &&
           nc->recv_mbuf.len == 0)) {
        return send_some(nc);
      }
      move_or_append_mbuf(&nc->recv_mbuf, &ctx->hs_recv_mbuf);
      mbuf_trim(&ctx->hs_recv_mbuf);
      ctx->hs_state = MGOS_SSL_IF_MBED_HS_STATE_PENDING;
      mgos_invoke_cb(mgos_ssl_if_mbed_handshake, nc, MGOS_INVOKE_CB_F_BG_TASK);
      return MG_SSL_WANT_READ;
    case MGOS_SSL_IF_MBED_HS_STATE_PENDING:
      return MG_SSL_WANT_READ;
    case MGOS_SSL_IF_MBED_HS_STATE_DONE:
      ctx->hs_state = MGOS_SSL_IF_MBED_HS_STATE_IDLE;
      if (nc->send_mbuf.len > 0) send_some(nc);
      return mg_ssl_if_handshake_common(nc, ctx->hs_result);
  }
  return MG_SSL_WANT_READ;
}

enum mg_ssl_if_result mg_ssl_if_handshake_direct(struct mg_connection *nc) {
  assert(!(nc->flags & MG_F_SSL_HANDSHAKE_DONE));
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  int res = mbedtls_ssl_handshake(ctx->ssl);
  DBG(("%p mbedtls_ssl_handshake() -> %d", nc, res));
  return mg_ssl_if_handshake_common(nc, res);
}

int mg_ssl_if_read(struct mg_connection *nc, void *buf, size_t len) {
  assert(nc->flags & MG_F_SSL_HANDSHAKE_DONE);
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  int n = mbedtls_ssl_read(ctx->ssl, (unsigned char *) buf, len);
  DBG(("%p SSL <- %d", nc, n));
  if (n < 0) return mg_ssl_if_mbed_err(nc, n);
  if (n == 0) nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  return n;
}

int mg_ssl_if_write(struct mg_connection *nc, const void *buf, size_t len) {
  assert(nc->flags & MG_F_SSL_HANDSHAKE_DONE);
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  /* Per mbedTLS docs, if write returns WANT_READ or WANT_WRITE, the operation
   * should be retried with the same data and length.
   * Here we assume that the data being pushed will remain the same but the
   * amount may grow between calls so we save the length that was used and
   * retry. The assumption being that the data itself won't change and won't
   * be removed. */
  size_t l = len;
  if (ctx->saved_len > 0 && ctx->saved_len < l) l = ctx->saved_len;
  int n = mbedtls_ssl_write(ctx->ssl, (const unsigned char *) buf, l);
  DBG(("%p SSL -> %d,%d,%d -> %d", nc, (int) len, (int) ctx->saved_len, (int) l,
       n));
  if (n < 0) {
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
      ctx->saved_len = len;
    }
    return mg_ssl_if_mbed_err(nc, n);
  } else if (n > 0) {
    ctx->saved_len = 0;
  }
  return n;
}

void mg_ssl_if_conn_close_notify(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  if (ctx == NULL || !(nc->flags & MG_F_SSL_HANDSHAKE_DONE)) return;
  mbedtls_ssl_close_notify(ctx->ssl);
}

void mg_ssl_if_conn_free(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = nc->ssl_if_data;
  if (ctx == NULL) return;
  nc->ssl_if_data = NULL;
  if (ctx->ssl != NULL) {
    mbedtls_ssl_free(ctx->ssl);
    free(ctx->ssl);
  }
  if (ctx->conf != NULL) {
    mbedtls_ssl_config_free(ctx->conf);
    free(ctx->conf);
  }
  mg_ssl_if_mbed_free_certs_and_keys(ctx);
  mbuf_free(&ctx->cipher_suites);
  memset(ctx, 0, sizeof(*ctx));
  free(ctx);
}

static enum mg_ssl_if_result mg_use_ca_cert(struct mg_ssl_if_ctx *ctx,
                                            const char *ca_cert) {
  if (ca_cert == NULL || strcmp(ca_cert, "*") == 0) {
    mbedtls_ssl_conf_authmode(ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
    return MG_SSL_OK;
  }
#ifdef MBEDTLS_X509_CA_CHAIN_ON_DISK
  ctx->ca_chain_file = strdup(ca_cert);
  if (ctx->ca_chain_file == NULL) return MG_SSL_ERROR;
  if (mbedtls_ssl_conf_ca_chain_file(ctx->conf, ctx->ca_chain_file, NULL) !=
      0) {
    return MG_SSL_ERROR;
  }
#else
  ctx->ca_cert = (mbedtls_x509_crt *) calloc(1, sizeof(*ctx->ca_cert));
  mbedtls_x509_crt_init(ctx->ca_cert);
  if (mbedtls_x509_crt_parse_file(ctx->ca_cert, ca_cert) != 0) {
    return MG_SSL_ERROR;
  }
  mbedtls_ssl_conf_ca_chain(ctx->conf, ctx->ca_cert, NULL);
#endif
  mbedtls_ssl_conf_authmode(ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_use_cert(struct mg_ssl_if_ctx *ctx,
                                         const char *cert, const char *key,
                                         const char **err_msg) {
  if (key == NULL) key = cert;
  if (cert == NULL || cert[0] == '\0' || key == NULL || key[0] == '\0') {
    return MG_SSL_OK;
  }
  ctx->cert = calloc(1, sizeof(*ctx->cert));
  mbedtls_x509_crt_init(ctx->cert);
  ctx->key = calloc(1, sizeof(*ctx->key));
  mbedtls_pk_init(ctx->key);
  if (mbedtls_x509_crt_parse_file(ctx->cert, cert) != 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL cert");
    return MG_SSL_ERROR;
  }
  if (mbedtls_pk_parse_keyfile(ctx->key, key, NULL) != 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL key");
    return MG_SSL_ERROR;
  }
  if (mbedtls_ssl_conf_own_cert(ctx->conf, ctx->cert, ctx->key) != 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL key or cert");
    return MG_SSL_ERROR;
  }
  return MG_SSL_OK;
}

static const int mg_s_cipher_list[] = {
#if CS_PLATFORM != CS_P_ESP8266
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
#else
    /*
     * ECDHE is way too slow on ESP8266 w/o cryptochip, this sometimes results
     * in WiFi STA deauths. Use weaker but faster cipher suites. Sad but true.
     * Disable DHE completely because it's just hopelessly slow.
     */
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
#endif /* CS_PLATFORM != CS_P_ESP8266 */
    0,
};

/*
 * Ciphers can be specified as a colon-separated list of cipher suite names.
 * These can be found in
 * https://github.com/ARMmbed/mbedtls/blob/development/library/ssl_ciphersuites.c#L267
 * E.g.: TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CCM
 */
static enum mg_ssl_if_result mg_set_cipher_list(struct mg_ssl_if_ctx *ctx,
                                                const char *ciphers) {
  if (ciphers != NULL) {
    int l, id;
    const char *s = ciphers, *e;
    char tmp[50];
    while (s != NULL) {
      e = strchr(s, ':');
      l = (e != NULL ? (e - s) : (int) strlen(s));
      strncpy(tmp, s, l);
      tmp[l] = '\0';
      id = mbedtls_ssl_get_ciphersuite_id(tmp);
      DBG(("%s -> %04x", tmp, id));
      if (id != 0) {
        mbuf_append(&ctx->cipher_suites, &id, sizeof(id));
      }
      s = (e != NULL ? e + 1 : NULL);
    }
    if (ctx->cipher_suites.len == 0) return MG_SSL_ERROR;
    id = 0;
    mbuf_append(&ctx->cipher_suites, &id, sizeof(id));
    mbuf_trim(&ctx->cipher_suites);
    mbedtls_ssl_conf_ciphersuites(ctx->conf,
                                  (const int *) ctx->cipher_suites.buf);
  } else {
    mbedtls_ssl_conf_ciphersuites(ctx->conf, mg_s_cipher_list);
  }
  return MG_SSL_OK;
}

#ifdef MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
static enum mg_ssl_if_result mg_ssl_if_mbed_set_psk(struct mg_ssl_if_ctx *ctx,
                                                    const char *identity,
                                                    const char *key_str) {
  unsigned char key[32];
  size_t key_len;
  if (identity == NULL && key_str == NULL) return MG_SSL_OK;
  if (identity == NULL || key_str == NULL) return MG_SSL_ERROR;
  key_len = strlen(key_str);
  if (key_len != 32 && key_len != 64) return MG_SSL_ERROR;
  size_t i = 0;
  memset(key, 0, sizeof(key));
  key_len = 0;
  for (i = 0; key_str[i] != '\0'; i++) {
    unsigned char c;
    char hc = tolower((int) key_str[i]);
    if (hc >= '0' && hc <= '9') {
      c = hc - '0';
    } else if (hc >= 'a' && hc <= 'f') {
      c = hc - 'a' + 0xa;
    } else {
      return MG_SSL_ERROR;
    }
    key_len = i / 2;
    key[key_len] <<= 4;
    key[key_len] |= c;
  }
  key_len++;
  DBG(("identity = '%s', key = (%u)", identity, (unsigned int) key_len));
  /* mbedTLS makes copies of psk and identity. */
  if (mbedtls_ssl_conf_psk(ctx->conf, (const unsigned char *) key, key_len,
                           (const unsigned char *) identity,
                           strlen(identity)) != 0) {
    return MG_SSL_ERROR;
  }
  return MG_SSL_OK;
}
#endif

const char *mg_set_ssl(struct mg_connection *nc, const char *cert,
                       const char *ca_cert) {
  const char *err_msg = NULL;
  struct mg_ssl_if_conn_params params;
  memset(&params, 0, sizeof(params));
  params.cert = cert;
  params.ca_cert = ca_cert;
  if (mg_ssl_if_conn_init(nc, &params, &err_msg) != MG_SSL_OK) {
    return err_msg;
  }
  return NULL;
}

#endif  // MG_ENABLE_SSL && MG_SSL_IF == MG_SSL_IF_MBEDTLS_MGOS
