#pragma once


#include <json-c/json.h>
#ifdef APACHE
    #include <httpd.h>
    #include <http_request.h>
    #include <http_core.h>
    #include <http_protocol.h>
    #include <http_log.h>
    typedef request_rec SSORestRequestObject;
    typedef apr_pool_t SSORestPluginPool;
    typedef apr_array_header_t ssorest_array_t;
    typedef unsigned int UINT;
    #define ssorest_pcalloc(pool, size) (apr_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (apr_palloc(pool, size))
    #define logEmerg(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_EMERG,   0,  r->server, __VA_ARGS__)
    #define logAlert(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_ALERT,   0,  r->server, __VA_ARGS__)
    #define logCrit(r,   ...) 	ap_log_error(APLOG_MARK, APLOG_CRIT,    0,  r->server, __VA_ARGS__)
    #define logError(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_ERR,     0,  r->server, __VA_ARGS__)
    #define logWarn(r,   ...) 	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,  r->server, __VA_ARGS__)
    #define logNotice(r, ...) 	ap_log_error(APLOG_MARK, APLOG_NOTICE,  0,  r->server, __VA_ARGS__)
    #define logInfo(r,   ...) 	ap_log_error(APLOG_MARK, APLOG_INFO,    0,  r->server, __VA_ARGS__)
    #define logDebug(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_DEBUG,   0,  r->server, __VA_ARGS__)

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
    #define logEmerg(r,  ...) 	ngx_log_error_core(NGX_LOG_EMERG,   r->connection->log, 0, __VA_ARGS__)
    #define logAlert(r,  ...) 	ngx_log_error_core(NGX_LOG_ALERT,   r->connection->log, 0, __VA_ARGS__)
    #define logCrit(r,   ...) 	ngx_log_error_core(NGX_LOG_CRIT,    r->connection->log, 0, __VA_ARGS__)
    #define logError(r,  ...) 	ngx_log_error_core(NGX_LOG_ERR,     r->connection->log, 0, __VA_ARGS__)
    #define logWarn(r,   ...) 	ngx_log_error_core(NGX_LOG_WARNING, r->connection->log, 0, __VA_ARGS__)
    #define logNotice(r, ...) 	ngx_log_error_core(NGX_LOG_NOTICE,  r->connection->log, 0, __VA_ARGS__)
    #define logInfo(r,   ...) 	ngx_log_error_core(NGX_LOG_INFO,    r->connection->log, 0, __VA_ARGS__)
    #define logDebug(r,  ...) 	ngx_log_error_core(NGX_LOG_DEBUG,   r->connection->log, 0, __VA_ARGS__)
#endif


typedef struct SSORestPlugin SSORestPlugin;
typedef struct SSORestPluginConfigration SSORestPluginConfigration;
typedef json_object JSonGatewayRequest;
