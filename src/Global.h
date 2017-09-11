/**
 * @file   Global.h
 * @author Egor Lord <elord@idfconnect.com>
 *
 */
 
#pragma once
#ifdef APACHE
    #include <httpd.h>
    #include <http_request.h>
    #include <http_core.h>
    #include <http_protocol.h>
    #include <http_log.h>
    typedef request_rec SSORestRequestObject;
    typedef apr_pool_t SSORestPluginPool;
    typedef apr_array_header_t ssorest_array_t;
    typedef apr_table_t ssorest_table_t;
    typedef unsigned int UINT;
    #define SSOREST_DECLINED (DECLINED)
    #define SSOREST_OK (OK)
    #define ssorest_pcalloc(pool, size) (apr_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (apr_palloc(pool, size))
    #define ssorest_array_create(pool, nelts, elt_size) (apr_array_make(pool, nelts, elt_size))
    #define ssorest_array_push(arr) (apr_array_push(arr))
    #define ssorest_table_set(table, key, value) (apr_table_set(table, key, value))

#elif NGINX
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
    typedef ngx_http_request_t SSORestRequestObject;
    typedef ngx_pool_t SSORestPluginPool;
    typedef ngx_array_t ssorest_array_t;
    typedef ngx_table_elt_t ssorest_table_t;
    typedef ngx_uint_t UINT;
    #define SSOREST_DECLINED (NGX_DECLINED)
    #define SSOREST_OK (NGX_OK)
    #define ssorest_pcalloc(pool, size) (ngx_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (ngx_palloc(pool, size))
    #define ssorest_array_create(pool, nelts, elt_size)     (ngx_array_create(pool, nelts, elt_size))
    #define ssorest_array_push(arr) (ngx_array_push(arr))
    void ssorest_table_set(ngx_list_t *header, const char *key, const char *value);
#endif

#define SSOREST_ERROR               (SSOREST_DECLINED)
#define SSOREST_SC_NOT_EXTENDED     510
#define SSOREST_SC_EXTENDED         100
#define SSOREST_INTERNAL_ERROR      500
#define SSOREST_BAD_GATEWAY         502
#define RANDOMTEXT_ATTR             "randomText"
#define RANDOMTEXT_SIGNED_ATTR      "randomTextSigned"
#define CHALLENGE_HEADER_NAME       "Challenge"
#define GATEWAY_TOKEN_NAME          "gatewayToken"
#define SIGNATURE_NEEDED            "Signature Needed"
#define HEADERS_IN                  1
#define HEADERS_OUT                 0
#define SSOREST_WRONG_PARAMETER     0
#define SSOREST_NOT_FOUND           1

