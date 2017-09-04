#include "JsonGatewayRequest.h"
#include "Util.h"
JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject* request)
{
    JSonGatewayRequest *jsonGatewayRequest = json_object_new_object();

    // method
    json_object_object_add(jsonGatewayRequest, "method", json_object_new_string(getMethod(request)));
    
    // url
    json_object_object_add(jsonGatewayRequest, "url", json_object_new_string(getUrl(request)));
    
    // protocol
    json_object_object_add(jsonGatewayRequest, "protocol", json_object_new_string(getProtocol(request)));

    // characterEncoding
    json_object_object_add(jsonGatewayRequest, "characterEncoding", json_object_new_string(getCharacterEncoding(request)));

    // contentLength
    json_object_object_add(jsonGatewayRequest, "contentLength", json_object_new_int(getContentLength(request)));

    // contentType
    json_object_object_add(jsonGatewayRequest, "contentType", json_object_new_string(getContentType(request)));

    // contextPath
    json_object_object_add(jsonGatewayRequest, "contextPath", json_object_new_string(getContextPath(request)));

    // localAddr
    json_object_object_add(jsonGatewayRequest, "localAddr", json_object_new_string(getLocalAddr(request)));

    // localName
    json_object_object_add(jsonGatewayRequest, "localName", json_object_new_string(getLocalName(request)));

    // localPort
    json_object_object_add(jsonGatewayRequest, "localPort", json_object_new_int(getLocalPort(request)));

    // remoteAddr
    json_object_object_add(jsonGatewayRequest, "remoteAddr", json_object_new_string(getRemoteAddr(request)));

    // remoteHost
    json_object_object_add(jsonGatewayRequest, "remoteHost", json_object_new_string(getRemoteHost(request)));

    // remotePort
    json_object_object_add(jsonGatewayRequest, "remotePort", json_object_new_int(getRemotePort(request)));

    // secure
    json_object_object_add(jsonGatewayRequest, "secure", json_object_new_boolean(getSecure(request)));

    // scheme
    json_object_object_add(jsonGatewayRequest, "scheme", json_object_new_string(getScheme(request)));

    // serverName
    json_object_object_add(jsonGatewayRequest, "serverName", json_object_new_string(getServerName(request)));

    // serverPort
    json_object_object_add(jsonGatewayRequest, "serverPort", json_object_new_int(getServerPort(request)));

    // servletPath
    json_object_object_add(jsonGatewayRequest, "servletPath", json_object_new_string(""));

    // locales
    json_object* jsonarray_locale = json_object_new_array();
    ssorest_array_t* locales = getLocales(request);
    UINT i;
    for (i = 0; i < locales->nelts; i++)
    {
        #ifdef APACHE
        const char *s = ((const char**)locales->elts)[i];
        json_object_array_add(jsonarray_locale, json_object_new_string((char*) s));
        #elif NGINX

        #endif
        
    }
    json_object_object_add(jsonGatewayRequest, "locales", jsonarray_locale);

    // headers
    json_object* jsonGatewayRequestHeaders = json_object_new_object();
    
    // headers: accept-language
    json_object* jsonHeaderAcceptLanguage = json_object_new_array();
    json_object_array_add(jsonHeaderAcceptLanguage, json_object_new_string(getAcceptLanguage(request)));
    json_object_object_add(jsonGatewayRequestHeaders, "accept-language", jsonHeaderAcceptLanguage);

    // headers: connection
    json_object* jsonHeaderConnection = json_object_new_array();
    json_object_array_add(jsonHeaderConnection, json_object_new_string(getConnection(request)));
    json_object_object_add(jsonGatewayRequestHeaders, "connection", jsonHeaderConnection);

    // headers: accept
    json_object* jsonHeaderAccept = json_object_new_array();
    json_object_array_add(jsonHeaderAccept, json_object_new_string(getAccept(request)));
    json_object_object_add(jsonGatewayRequestHeaders, "accept", jsonHeaderAccept);

    // headers: host
    json_object* jsonHeaderHost = json_object_new_array();
    json_object_array_add(jsonHeaderHost, json_object_new_string(getHost(request)));
    json_object_object_add(jsonGatewayRequestHeaders, "host", jsonHeaderHost);

    // headers: accept-encoding
    json_object* jsonHeaderAcceptEncoding = json_object_new_array();
    json_object_array_add(jsonHeaderAcceptEncoding, json_object_new_string(getAcceptEncoding(request)));
    json_object_object_add(jsonGatewayRequestHeaders, "accept-encoding", jsonHeaderAcceptEncoding);

    // headers: user-agent
    json_object* jsonHeaderUserAgent = json_object_new_array();
    json_object_array_add(jsonHeaderUserAgent, json_object_new_string(getUserAgent(request)));
    json_object_object_add(jsonGatewayRequestHeaders, "user-agent", jsonHeaderUserAgent);

    // headers
    json_object_object_add(jsonGatewayRequest, "headers", jsonGatewayRequestHeaders);

    // // cookies
    
    // // parameters

    // // attributes
    return jsonGatewayRequest;
}

void setJsonGatewayRequestAttributes(JSonGatewayRequest* self, const char* key, const char* value)
{
    
}

void sendJsonGatewayRequest(const char* gatewayUrl)
{
    
}

const char* getMethod(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->method? r->method : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getUrl(SSORestRequestObject* r)
{
#ifdef APACHE
    return ap_construct_url(r->pool, r->uri, r);
#elif NGINX
    const char *server_name = getServerName(r);
    const char *scheme = getScheme(r);
    int  port = getServerPort(r);

    if (isDefaultPort(port))
    {
        return ssorest_pstrcat(r->pool, scheme, "://", server_name, (char *) r->uri.data, NULL);
    }

    char *portwithcomma = ngx_pnalloc(r->pool, sizeof(":65535") - 1);
    ngx_sprintf((u_char *) portwithcomma, ":ui", port);
    return ssorest_pstrcat(r->pool, scheme, "://", server_name, portwithcomma, (char *) r->uri.data, NULL);
#endif
}
const char* getUri(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->uri? r->uri : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getProtocol(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    if (r->main)
        rv = r->main->protocol;
    else
        rv = r->protocol;
    #elif NGINX

    #endif

    return rv;
}
const char* getCharacterEncoding(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->content_encoding? r->content_encoding : "";
    #elif NGINX

    #endif

    return rv;
}
int getContentLength(SSORestRequestObject* r)
{
    int rv; 
    #ifdef APACHE
    rv = r->clength? r->clength : 0;
    #elif NGINX

    #endif

    return rv;
}
const char* getContentType(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->content_type? r->content_type : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getContextPath(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = ap_document_root(r);
    #elif NGINX

    #endif

    return rv;
}
const char* getLocalAddr(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->connection->local_ip? r->connection->local_ip : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getLocalName(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->server->server_hostname? r->server->server_hostname : "";
    #elif NGINX

    #endif

    return rv;
}
int getLocalPort(SSORestRequestObject* r)
{
    int rv = 0;
    #ifdef APACHE
    rv = r->server->port;
    if (rv == 0)
    {
        if (r->server->addrs)
            rv = r->server->addrs->host_port;
    }
    #elif NGINX

    #endif

    return rv;
}
const char* getRemoteAddr(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
        rv = r->useragent_ip? r->useragent_ip : "";
    #elif NGINX
        rv = makeNullTerminated(r->pool, r->connection->addr_text.data, r->connection->addr_text.len);
    #endif

    return rv;
}
const char* getRemoteHost(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->useragent_ip? r->useragent_ip : "";
    #elif NGINX

    #endif

    return rv;
}
int getRemotePort(SSORestRequestObject* r)
{
    UINT rv = 0;
    #ifdef APACHE
        rv = r->useragent_addr->port? r->useragent_addr->port : 0;
    #elif NGINX
        rv = ngx_inet_get_port(r->connection->sockaddr);
    #endif

    return rv;
}
int getSecure(SSORestRequestObject* r)
{
    int rv = 0;
    const char* scheme = getScheme(r);
    if(!strcasecmp(scheme, "https"))
        rv = 1;
    return rv;
}
const char* getScheme(SSORestRequestObject* r)
{
    const char *rv;
    #ifdef APACHE
        rv = ap_http_scheme(r);
    #elif NGINX
        #if (NGX_HTTP_SSL)
            if (r->connection->ssl) rv = "https";
        #else
            rv = "http";
        #endif
    #endif
    return rv;
}
const char* getServerName(SSORestRequestObject* r)
{
    const char* rv;
    #ifdef APACHE
    rv = r->server->server_hostname? r->server->server_hostname : "";
    #elif NGINX

    #endif

    return rv;
}
int getServerPort(SSORestRequestObject* r)
{
    int rv = 0;
    #ifdef APACHE
    rv = r->server->port;
    if (rv == 0)
    {
        if (r->server->addrs)
            rv = r->server->addrs->host_port;
    }
    #elif NGINX

    #endif

    return rv;
}
ssorest_array_t* getLocales(SSORestRequestObject* r)
{
    const char *start;
    const char *end;
    const char *pos;
    ssorest_array_t *langs_array = NULL;
    #ifdef APACHE
        start = apr_table_get(r->headers_in, "Accept-Language");
        end = start + strlen(start);
        langs_array = apr_array_make(r->pool, 1, sizeof(const char*));
    #elif NGINX
        start = r->headers_in.accept_language? (char *) r->headers_in.accept_language->value.data : NULL;
        end = start? (start + r->headers_in.accept_language->value.len) : (NULL);
        langs_array = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));
    #endif
    
    while (start < end) {
        while (start < end && *start == ' ') {
            start++;
        }
        pos = start;
        while (pos < end && *pos != ',' && *pos != ';') {
            pos++;
        }
        char *lang = ssorest_pcalloc(r->pool, (pos-start) + 1);
        memcpy(lang, start, pos-start);
        lang[pos-start] = '\0';
        #ifdef APACHE
            *((const char **) apr_array_push(langs_array)) = lang;
        #elif NGINX
            ngx_str_t* ele = ngx_array_push(langs_array);
            ele->len = pos-start;
            ele->data = (u_char *) lang;
        #endif

        // We discard the quality value
        if (*pos == ';') {
            while (pos < end && *pos != ',') {
                pos++;
            }
        }
        if (*pos == ',') {
            pos++;
        }

        start = pos;
    }
    return langs_array;
}
const char* getAcceptLanguage(SSORestRequestObject* r)
{
    const char *rv;
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Accept-Language");
    #elif NGINX
        #if (NGX_HTTP_HEADERS)
            ngx_http_variable_value_t *v;
            v = ngx_pcalloc(r->pool, sizeof(ngx_http_variable_value_t));
            get_ngx_http_request_headers(r, v, offsetof(ngx_http_request_t, headers_in.accept_language));
            rv = toStringSafety(r->pool, v);
        #else
            rv = NULL;
        #endif
    #endif
    return rv;
}
const char* getConnection(SSORestRequestObject* r)
{
    const char *rv;
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Connection");
    #elif NGINX
        if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
            rv = "upgrade";
        }
        else if (r->keepalive) {
            rv = "keep-alive";
        }
        else {
            rv = "close";
        }
    #endif
    return rv;
}
const char* getAccept(SSORestRequestObject* r)
{
    const char *rv;
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Accept");
    #elif NGINX
        #if (NGX_HTTP_HEADERS)
            ngx_http_variable_value_t *v;
            v = ngx_pcalloc(r->pool, sizeof(ngx_http_variable_value_t));
            get_ngx_http_request_headers(r, v, offsetof(ngx_http_request_t, headers_in.accept));
            rv = toStringSafety(r->pool, v);
        #else
            rv = NULL;
        #endif
    #endif
    return rv;
}
const char* getHost(SSORestRequestObject* r)
{
    const char *rv;
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Host");
    #elif NGINX

    #endif
    return rv;
}
const char* getAcceptEncoding(SSORestRequestObject* r)
{
    const char *rv;
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Accept-Encoding");
    #elif NGINX

    #endif
    return rv;
}
const char* getUserAgent(SSORestRequestObject* r)
{
    const char *rv;
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "User-Agent");
    #elif NGINX

    #endif
    return rv;
}
int isDefaultPort(int port)
{
    return (port == 80);
}

#ifdef NGINX
ngx_int_t get_ngx_http_request_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_table_elt_t *h;
    h = *(ngx_table_elt_t **) ((char *) r + data);

    if (h) {
        v->len = h->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = h->value.data;

    }
    else {
        v->not_found = 1;
    }
    return NGX_OK;
}
#endif