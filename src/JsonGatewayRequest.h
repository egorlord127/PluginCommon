#pragma once

#include <json-c/json.h>
#include "Global.h"

JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject*);
void sendJsonGatewayRequest(const char*);
void setJsonGatewayRequestAttributes(JSonGatewayRequest* , const char*, const char*);

const char*         getMethod(SSORestRequestObject*);
const char*         getUrl(SSORestRequestObject*);
const char*         getUri(SSORestRequestObject* r);
const char*         getProtocol(SSORestRequestObject*);
const char*         getCharacterEncoding(SSORestRequestObject*);
int                 getContentLength(SSORestRequestObject*);
const char*         getContentType(SSORestRequestObject*);
const char*         getContextPath(SSORestRequestObject*);
const char*         getLocalAddr(SSORestRequestObject*);
const char*         getLocalName(SSORestRequestObject*);
int                 getLocalPort(SSORestRequestObject*);
const char*         getRemoteAddr(SSORestRequestObject*);
const char*         getRemoteHost(SSORestRequestObject*);
int                 getRemotePort(SSORestRequestObject*);
int                 getSecure(SSORestRequestObject*);
const char*         getScheme(SSORestRequestObject*);
const char*         getServerName(SSORestRequestObject*);
int                 getServerPort(SSORestRequestObject*);
ssorest_array_t*    getLocales(SSORestRequestObject*);
const char*         getAcceptLanguage(SSORestRequestObject*);
const char*         getConnection(SSORestRequestObject*);
const char*         getAccept(SSORestRequestObject*);
const char*         getHost(SSORestRequestObject*);
const char*         getAcceptEncoding(SSORestRequestObject*);
const char*         getUserAgent(SSORestRequestObject*);
int                 isDefaultPort(int port);

#ifdef NGINX
ngx_int_t get_ngx_http_request_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
#endif