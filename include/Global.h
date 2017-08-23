#pragma once


#include <json-c/json.h>
#ifdef APACHE
    #include <httpd.h>
    typedef request_rec SSORestRequestObject;
    typedef apr_pool_t SSORestPluginPool;
    #define ssorest_pcalloc(pool, size) (apr_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (apr_palloc(pool, size))
#elif NGINX
    #include <ngx_config.h>
    #include <ngx_core.h>
    typedef ngx_http_request_t SSORestRequestObject;
    typedef ngx_pool_t SSORestPluginPool;
    #define ssorest_pcalloc(pool, size) (ngx_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (ngx_palloc(pool, size))
#endif


typedef struct SSORestPlugin SSORestPlugin;
typedef struct SSORestPluginConfigration SSORestPluginConfigration;
typedef json_object JSonGatewayRequest;
