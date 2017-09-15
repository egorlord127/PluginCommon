/**
 * @file   RequestInfo.h
 * @author Egor Lord <elord@idfconnect.com>
 *
 */
 
#include "Global.h"
#include "SSORestPlugin.h"
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
const char*         getRequestArgs(SSORestRequestObject*);
int                 getRemotePort(SSORestRequestObject*);
int                 getSecure(SSORestRequestObject*);
const char*         getScheme(SSORestRequestObject*);
const char*         getServerName(SSORestRequestObject*);
int                 getServerPort(SSORestRequestObject*);
ssorest_array_t*    getLocales(SSORestRequestObject*);
const char*         getCookies(SSORestRequestObject* r);
const char*         getAcceptLanguage(SSORestRequestObject*);
const char*         getConnection(SSORestRequestObject*);
const char*         getAccept(SSORestRequestObject*);
const char*         getHost(SSORestRequestObject*);
const char*         getAcceptEncoding(SSORestRequestObject*);
const char*         getUserAgent(SSORestRequestObject*);
int                 isDefaultPort(int port);
const char*         getRequestFileExtension(SSORestRequestObject*);
const char*         getFileContextPath(SSORestRequestObject*);