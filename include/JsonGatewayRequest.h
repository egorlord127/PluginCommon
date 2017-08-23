#pragma once

#include <json-c/json.h>
#include "Global.h"

JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject*);
void sendJsonGatewayRequest(const char*);
void setJsonGatewayRequestAttributes(JSonGatewayRequest* , const char*, const char*);

const char* getMethod(SSORestRequestObject*);
const char* getUrl(SSORestRequestObject*);
const char* getProtocol(SSORestRequestObject*);
const char* getCharacterEncoding(SSORestRequestObject*);
int getContentLength(SSORestRequestObject*);
const char* getContentType(SSORestRequestObject*);
const char* getContextPath(SSORestRequestObject*);
const char* getLocalAddr(SSORestRequestObject*);
const char* getLocalName(SSORestRequestObject*);
int getLocalPort(SSORestRequestObject*);
const char* getRemoteAddr(SSORestRequestObject*);
const char* getRemoteHost(SSORestRequestObject*);
int getRemotePort(SSORestRequestObject*);
// const char* getSecure(SSORestRequestObject*);
// const char* getScheme(SSORestRequestObject*);
// const char* getServerName(SSORestRequestObject*);
// const char* getServerPort(SSORestRequestObject*);
// const char* getServletPath(SSORestRequestObject*);
// const char* getLocales(SSORestRequestObject*);
// const char* getAcceptLanguage(SSORestRequestObject*);
// const char* getConnection(SSORestRequestObject*);
// const char* getAccept(SSORestRequestObject*);
// const char* getHost(SSORestRequestObject*);
// const char* getAcceptEncoding(SSORestRequestObject*);
// const char* getUserAgent(SSORestRequestObject*);