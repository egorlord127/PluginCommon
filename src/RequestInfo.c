/**
 * @file   RequestInfo.c
 * @author Egor Lord <elord@idfconnect.com>
 *
 */
#include "RequestInfo.h"
#include "Util.h"
#include "Logging.h"
const char* getMethod(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->method? r->method : "";
    #elif NGINX
        rv = r->main->method_name.data? toStringSafety(r->pool, r->main->method_name.data, r->main->method_name.len) : "";
    #endif

    return rv;
}
const char* getUrl(SSORestRequestObject* r)
{
    #ifdef APACHE
        return ap_construct_url(r->pool, r->unparsed_uri, r);
    #elif NGINX
        const char *server_name = getServerName(r);
        const char *scheme = getScheme(r);
        int  port = getServerPort(r);

        if (isDefaultPort(port))
        {
            return ssorest_pstrcat(r->pool, scheme, "://", server_name, toStringSafety(r->pool, r->unparsed_uri.data, r->unparsed_uri.len), NULL);
        }

        char *portwithcomma = ngx_pnalloc(r->pool, sizeof(":65535"));
        int len = ngx_sprintf((u_char *) portwithcomma, ":%ui", port) - (u_char *) portwithcomma;
        portwithcomma[len] = '\0';
        return ssorest_pstrcat(r->pool, scheme, "://", server_name, portwithcomma, toStringSafety(r->pool, r->unparsed_uri.data, r->unparsed_uri.len), NULL);
    #endif
}

const char* getProtocol(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->main? r->main->protocol : r->protocol;
    #elif NGINX
        rv = r->main->http_protocol.data?  toStringSafety(r->pool, r->main->http_protocol.data, r->main->http_protocol.len) : "";
    #endif

    return rv;
}
const char* getCharacterEncoding(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->content_encoding? r->content_encoding : "";
    #elif NGINX
        rv = r->headers_out.content_encoding? toStringSafety(r->pool, r->headers_out.content_encoding->value.data, r->headers_out.content_encoding->value.len) : "";
    #endif

    return rv;
}
int getContentLength(SSORestRequestObject* r)
{
    int rv = 0; 
    #ifdef APACHE
        rv = r->clength? r->clength : 0;
    #elif NGINX
        rv = r->headers_in.content_length_n;
    #endif

    return rv;
}
const char* getContentType(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->content_type? r->content_type : "";
    #elif NGINX
        ngx_table_elt_t *h = *(ngx_table_elt_t **) ((char *) r + offsetof(ngx_http_request_t, headers_in.content_type));
        rv = h? toStringSafety(r->pool, h->value.data, h->value.len) : "";
    #endif

    return rv;
}
const char* getContextPath(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = ap_document_root(r);
    #elif NGINX
        ngx_str_t path;
        ngx_http_core_loc_conf_t *clcf;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->root_lengths == NULL) {
            rv = toStringSafety(r->pool, clcf->root.data, clcf->root.len);
        }
        else {
            if (ngx_http_script_run(r, &path, clcf->root_lengths->elts, 0,
                    clcf->root_values->elts)
                    == NULL)
            {
                logError(r, "Failed to get context path");
                return "";
            }

            if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
                    != NGX_OK)
            {
                logError(r, "Failed to get full context path");
                return "";
            }
            rv = toStringSafety(r->pool, path.data, path.len);
        }

    #endif

    return rv;
}
const char* getLocalAddr(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->connection->local_ip? r->connection->local_ip : "";
    #elif NGINX
        ngx_str_t s;
        u_char addr[NGX_SOCKADDR_STRLEN];

        s.len = NGX_SOCKADDR_STRLEN;
        s.data = addr;

        if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
            logError(r, "Failed to get local socket address");
            return "";
        }

        s.data = ngx_pnalloc(r->pool, s.len);
        if (s.data == NULL) {
            logError(r, "Failed to allocate memory");
            return "";
        }

        ngx_memcpy(s.data, addr, s.len);
        rv = toStringSafety(r->pool, s.data, s.len);
    #endif

    return rv;
}
const char* getLocalName(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->server->server_hostname? r->server->server_hostname : "";
    #elif NGINX
        ngx_http_core_srv_conf_t *cscf;
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
        rv = toStringSafety(r->pool, cscf->server_name.data, cscf->server_name.len);
    #endif

    return rv;
}
int getLocalPort(SSORestRequestObject* r)
{
    UINT rv = 0;
    #ifdef APACHE
        rv = r->server->port;
        if (rv == 0)
        {
            if (r->server->addrs)
                rv = r->server->addrs->host_port;
        }
    #elif NGINX
        rv = ngx_inet_get_port(r->connection->local_sockaddr);
    #endif

    return rv;
}
const char* getRemoteAddr(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->useragent_ip? r->useragent_ip : "";
    #elif NGINX
        rv = toStringSafety(r->pool, r->connection->addr_text.data, r->connection->addr_text.len);
    #endif

    return rv;
}
const char* getRemoteHost(SSORestRequestObject* r)
{
    const char *rv = ""; 
    #ifdef APACHE
        rv = r->useragent_ip? r->useragent_ip : "";
    #elif NGINX
        rv = toStringSafety(r->pool, r->connection->addr_text.data, r->connection->addr_text.len);
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
    const char *rv = "";
    #ifdef APACHE
        rv = ap_http_scheme(r);
    #elif NGINX
        rv = "http";
        #if (NGX_HTTP_SSL)
            if (r->connection->ssl) rv = "https";
        #endif
    #endif

    return rv;
}
const char* getServerName(SSORestRequestObject* r)
{
    const char *rv = "";
    #ifdef APACHE
        rv = r->server->server_hostname? r->server->server_hostname : "";
    #elif NGINX
        ngx_http_core_srv_conf_t *cscf;
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
        rv = toStringSafety(r->pool, cscf->server_name.data, cscf->server_name.len);
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
        rv = ngx_inet_get_port(r->connection->local_sockaddr);
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

const char* getCookies(SSORestRequestObject* r)
{
    #ifdef APACHE
        return apr_table_get(r->headers_in, "Cookie");
    #elif NGINX
        size_t len;
        u_char *p, *end;
        u_char sep = ';';
        ngx_uint_t i, n;
        ngx_array_t *a;
        ngx_table_elt_t **h;
        uintptr_t data = offsetof(ngx_http_request_t, headers_in.cookies);

        a = (ngx_array_t *) ((char *) r + data);

        n = a->nelts;
        h = a->elts;

        len = 0;

        for (i = 0; i < n; i++) {

            if (h[i]->hash == 0) {
                continue;
            }

            len += h[i]->value.len + 2;
        }

        if (len == 0) {
            return "";
        }

        len -= 2;

        if (n == 1) {
            return toStringSafety(r->pool, (*h)->value.data, (*h)->value.len);
        }

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return "";
        }

        end = p + len;

        for (i = 0; /* void */; i++) {

            if (h[i]->hash == 0) {
                continue;
            }

            p = ngx_copy(p, h[i]->value.data, h[i]->value.len);

            if (p == end) {
                break;
            }

            *p++ = sep;
            *p++ = ' ';
        }
        return toStringSafety(r->pool, p, len);
    #endif
}
const char* getAcceptLanguage(SSORestRequestObject* r)
{
    const char *rv = "";
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Accept-Language");
    #elif NGINX
        #if (NGX_HTTP_HEADERS)
            ngx_table_elt_t *h = *(ngx_table_elt_t **) ((char *) r + offsetof(ngx_http_request_t, headers_in.accept_language));
            rv = h? toStringSafety(r->pool, h->value.data, h->value.len) : "";
        #endif
    #endif

    return rv;
}
const char* getConnection(SSORestRequestObject* r)
{
    const char *rv = "";
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
    const char *rv = "";
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Accept");
    #elif NGINX
        #if (NGX_HTTP_HEADERS)
            ngx_table_elt_t *h = *(ngx_table_elt_t **) ((char *) r + offsetof(ngx_http_request_t, headers_in.accept));
            rv = h? toStringSafety(r->pool, h->value.data, h->value.len) : "";
        #endif
    #endif

    return rv;
}
const char* getHost(SSORestRequestObject* r)
{
    const char *rv = "";
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Host");
    #elif NGINX
        ngx_table_elt_t *h = *(ngx_table_elt_t **) ((char *) r + offsetof(ngx_http_request_t, headers_in.host));
        rv = h? toStringSafety(r->pool, h->value.data, h->value.len) : "";
    #endif

    return rv;
}
const char* getAcceptEncoding(SSORestRequestObject* r)
{
    const char *rv = "";
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "Accept-Encoding");
    #elif NGINX
        ngx_table_elt_t *h = *(ngx_table_elt_t **) ((char *) r + offsetof(ngx_http_request_t, headers_in.accept_encoding));
        rv = h? toStringSafety(r->pool, h->value.data, h->value.len) : "";
    #endif

    return rv;
}
const char* getUserAgent(SSORestRequestObject* r)
{
    const char *rv = "";
    #ifdef APACHE
        rv = apr_table_get(r->headers_in, "User-Agent");
    #elif NGINX
        ngx_table_elt_t *h = *(ngx_table_elt_t **) ((char *) r + offsetof(ngx_http_request_t, headers_in.user_agent));
        rv = h? toStringSafety(r->pool, h->value.data, h->value.len) : "";
    #endif

    return rv;
}
int isDefaultPort(int port)
{
    return (port == 80);
}

const char* getRequestArgs(SSORestRequestObject* r)
{
    const char *rv = "";
    #ifdef APACHE
        rv = r->args? r->args : "";
    #elif NGINX
        ngx_str_t *s = (ngx_str_t *) ((char *) r + offsetof(ngx_http_request_t, args));
        rv = s->data? toStringSafety(r->pool, s->data, s->len) : "";
    #endif

    return rv;
}

const char* getRequestFileExtension(SSORestRequestObject* r)
{
    const char *dot;
    const char *uri;
    #ifdef APACHE
        uri = r->uri;
    #elif NGINX
        uri = r->uri.data? toStringSafety(r->pool, r->uri.data, r->uri.len) : "";
    #endif
    
    dot = strrchr(uri, '.');
    if(!dot || dot == uri) return "";
    return dot + 1;
}

const char* getUri(SSORestRequestObject* r)
{
    const char *rv = "";
    #ifdef APACHE
        rv = r->uri? r->uri : "";
    #elif NGINX
        rv = r->uri.data? toStringSafety(r->pool, r->uri.data, r->uri.len) : "";
    #endif
    return rv;
}
