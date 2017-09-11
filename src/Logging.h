/**
 * @file   Logging.h
 * @author Egor Lord <elord@idfconnect.com>
 *
 */

#ifdef NGINX
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#define LOG_PREFIX "[SSORest]: "

#define CORE_MAX_ERROR_STR 8192

#define logEmerg(r,  ...) 	myCoreLog(NGX_LOG_EMERG,   r->connection->log, 0, __VA_ARGS__)
#define logAlert(r,  ...) 	myCoreLog(NGX_LOG_ALERT,   r->connection->log, 0, __VA_ARGS__)
#define logCrit(r,   ...) 	myCoreLog(NGX_LOG_CRIT,    r->connection->log, 0, __VA_ARGS__)
#define logError(r,  ...) 	myCoreLog(NGX_LOG_ERR,     r->connection->log, 0, __VA_ARGS__)
#define logWarn(r,   ...) 	myCoreLog(NGX_LOG_WARNING, r->connection->log, 0, __VA_ARGS__)
#define logNotice(r, ...) 	myCoreLog(NGX_LOG_NOTICE,  r->connection->log, 0, __VA_ARGS__)
#define logInfo(r,   ...) 	myCoreLog(NGX_LOG_INFO,    r->connection->log, 0, __VA_ARGS__)
#define logDebug(r,  ...) 	myCoreLog(NGX_LOG_DEBUG,   r->connection->log, 0, __VA_ARGS__)

#if (NGX_HAVE_VARIADIC_MACROS)
	void myCoreLog(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, const char *fmt, ...);
#else
	void myCoreLog(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, const char *fmt, va_list args);
#endif

#elif APACHE
#include <http_log.h>
#define logEmerg(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_EMERG,   0,  r->server, __VA_ARGS__)
#define logAlert(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_ALERT,   0,  r->server, __VA_ARGS__)
#define logCrit(r,   ...) 	ap_log_error(APLOG_MARK, APLOG_CRIT,    0,  r->server, __VA_ARGS__)
#define logError(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_ERR,     0,  r->server, __VA_ARGS__)
#define logWarn(r,   ...) 	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,  r->server, __VA_ARGS__)
#define logNotice(r, ...) 	ap_log_error(APLOG_MARK, APLOG_NOTICE,  0,  r->server, __VA_ARGS__)
#define logInfo(r,   ...) 	ap_log_error(APLOG_MARK, APLOG_INFO,    0,  r->server, __VA_ARGS__)
#define logDebug(r,  ...) 	ap_log_error(APLOG_MARK, APLOG_DEBUG,   0,  r->server, __VA_ARGS__)
#endif