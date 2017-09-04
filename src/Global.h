#pragma once


#include <json-c/json.h>
#ifdef APACHE
    #include <httpd.h>
    #include <http_request.h>
    #include <http_core.h>
    #include <httpd.h>
    typedef request_rec SSORestRequestObject;
    typedef apr_pool_t SSORestPluginPool;
    typedef apr_array_header_t ssorest_array_t;
    typedef unsigned int UINT;
    #define ssorest_pcalloc(pool, size) (apr_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (apr_palloc(pool, size))
#elif NGINX
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
    typedef ngx_http_request_t SSORestRequestObject;
    typedef ngx_pool_t SSORestPluginPool;
    typedef ngx_array_t ssorest_array_t;
    typedef ngx_uint_t UINT;
    #define ssorest_pcalloc(pool, size) (ngx_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (ngx_palloc(pool, size))
#endif


typedef struct SSORestPlugin SSORestPlugin;
typedef struct SSORestPluginConfigration SSORestPluginConfigration;
typedef json_object JSonGatewayRequest;
