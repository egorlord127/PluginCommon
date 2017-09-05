#include "Global.h"
#include "JsonGatewayRequest.h"
#include "JsonGatewayResponse.h"
#include "CurlWrapper.h"
#include "SSORestPlugin.h"
#include "Util.h"

static CURL* get_curl_session(SSORestRequestObject* r, SSORestPluginConfigration* conf);

#ifdef NGINX
static void ssorest_json_cleanup(void *data)
{
    json_object_put((json_object *) data);
}
static void ssorest_curl_easy_cleanup(void *data)
{
    curl_easy_cleanup((CURL *) data);
}
static void ssorest_curl_slist_free_all(void *data)
{
    curl_slist_free_all((struct curl_slist *) data);
}
#endif

JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject *request , SSORestPluginConfigration *conf)
{
    JSonGatewayRequest *jsonGatewayRequest = json_object_new_object();

    // Add Cleanup handler
    #ifdef APACHE
        apr_pool_cleanup_register(request->pool, jsonGatewayRequest, (void *) json_object_put, apr_pool_cleanup_null);
    #elif NGINX
        ngx_pool_cleanup_t  *cln;
        
        cln = ngx_pool_cleanup_add(request->pool, 0);
        if (cln == NULL) 
        {
             // TODO: Error Handling
        }
        
        cln->handler = ssorest_json_cleanup;
        cln->data = jsonGatewayRequest;
    #endif

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
            u_char *s = ((ngx_str_t *)locales->elts)[i].data;
            json_object_array_add(jsonarray_locale, json_object_new_string((char*) s));
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

    // cookies
    json_object* jsonGatewayRequestCookies = json_object_new_array();
    const char *cookiestring = getCookies(request);
    char *rest = (char *) cookiestring;
    char *cookie_name = NULL;
    char *cookie_value = NULL;
    char *cookie = NULL;
    while ((cookie = strtok_r(rest, "; ", &rest)))
    {
        json_object *json_cookies = json_object_new_object();

        cookie_name = ssorest_pcalloc(request->pool, strlen(cookie));
        cookie_value = ssorest_pcalloc(request->pool, strlen(cookie));
        sscanf(cookie, "%[^=]=%s", cookie_name, cookie_value);

        if(conf->ssoZone)
        {
            UINT i;
            UINT flag = 0;
            for(i = 0; i < conf->ssoZone->nelts; i++)
            {
                #ifdef APACHE
                    const char *ssozone = ((const char**)conf->ssoZone->elts)[i];
                    UINT ssozone_len = strlen(ssozone);
                #elif NGINX
                    const char *ssozone = (const char *) (((ngx_str_t *)conf->ssoZone->elts)[i].data);
                    UINT ssozone_len = ((ngx_str_t *)conf->ssoZone->elts)[i].len;
                #endif
                if (!strncasecmp((char *) cookie_name, ssozone, ssozone_len)) {
                    logError(request, "Transferring request cookie to JSon payload: %s=%s", cookie_name, cookie_value);
                    json_object_object_add(json_cookies, "name", json_object_new_string((const char*) cookie_name));
                    json_object_object_add(json_cookies, "value", json_object_new_string((const char*) cookie_value));
                    json_object_array_add(jsonGatewayRequestCookies, json_cookies);
                    flag = 1;
                    break;
                }
            }
            if(!flag)
                logError(request, "Skipping request cookie outside of our zone: %s", cookie_name);
        } else {
            logError(request, "Transferring request cookie to JSon payload: %s=%s", cookie_name, cookie_value);
            json_object_object_add(json_cookies, "name", json_object_new_string((const char*) cookie_name));
            json_object_object_add(json_cookies, "value", json_object_new_string((const char*) cookie_value));
            json_object_array_add(jsonGatewayRequestCookies, json_cookies); 
        }
    }
    json_object_object_add(jsonGatewayRequest, "cookies", jsonGatewayRequestCookies);

    // parameters
    if (conf->sendFormParameters)
    {
        json_object *jsonGatewayRequestParameters = json_object_new_object();
        json_object *json_temp = NULL;
        json_object *jsonarray_value;
        
        char *pair = NULL;
        char *saved = NULL;
        char *key = NULL;
        char *value = NULL;
        char *inner_args = NULL;
        char *inner_pair = NULL;
        char *inner_saved = NULL;
        char *inner_key = NULL;
        char *inner_value = NULL;
        
        char *args = (char *) getRequestArgs(request);
    
        for (pair = strtok_r(args, "&", &saved); pair; pair = strtok_r(NULL, "&", &saved)) {
            jsonarray_value = json_object_new_array();
            key = ssorest_pcalloc(request->pool, strlen(pair));
            value = ssorest_pcalloc(request->pool, strlen(pair));
            if (key == NULL || value == NULL)
            {
                logError(request, "Could not Allocate Memory");
            }
            sscanf(pair, "%[^=]=%s", key, value);
            json_object_object_get_ex(jsonGatewayRequestParameters, key, &json_temp);
            if (json_temp != NULL) {
                continue;
            }
    
            // Unescape querystring Value
            char *unesc_str = ssorest_pcalloc(request->pool, strlen(value) + 1);
            if (unesc_str == NULL)
            {
                logError(request, "Could not Allocate Memory");
            }
            unescape_str(value, unesc_str);
            json_object_array_add(jsonarray_value, json_object_new_string(unesc_str));
    
            inner_args = ssorest_pcalloc(request->pool, strlen(saved) + 1);
            memcpy(inner_args, saved, strlen(saved));
            inner_args[strlen(saved)] = '\0';
    
            for (inner_pair = strtok_r(inner_args, "&", &inner_saved); inner_pair;
                    inner_pair = strtok_r(NULL, "&", &inner_saved))
                            {
                inner_key = ssorest_pcalloc(request->pool, strlen(inner_pair));
                inner_value = ssorest_pcalloc(request->pool, strlen(inner_pair));
                sscanf(inner_pair, "%[^=]=%s", inner_key, inner_value);
    
                if (strcmp(key, inner_key) == 0)
                        {
                    // Unescape querystring Value
                    char *unesc_str = ssorest_pcalloc(request->pool, strlen(inner_value) + 1);
                    if (unesc_str == NULL)
                    {
                        logError(request, "Could not Allocate Memory");
                    }
                    unescape_str(inner_value, unesc_str);
                    json_object_array_add(jsonarray_value, json_object_new_string(unesc_str));
                }
            }
            json_object_object_add(jsonGatewayRequestParameters, key, jsonarray_value);
        }
        json_object_object_add(jsonGatewayRequest, "parameters", jsonGatewayRequestParameters);
    }
    

    // attributes
    json_object *jsonGatewayRequestAttributes = json_object_new_object();
    if (conf->acoName)
        json_object_object_add(jsonGatewayRequestAttributes, "acoName", json_object_new_string(conf->acoName));
    
    if (conf->pluginId) 
        json_object_object_add(jsonGatewayRequestAttributes, "pluginID", json_object_new_string(conf->pluginId));

    if (conf->gatewayToken) 
        json_object_object_add(jsonGatewayRequestAttributes, "gatewayToken", json_object_new_string(conf->gatewayToken));
    

    json_object_object_add(jsonGatewayRequest, "attributes", jsonGatewayRequestAttributes);

    return jsonGatewayRequest;
}

void setJsonGatewayRequestAttributes(JSonGatewayRequest* self, const char* key, const char* value)
{
    
}


/**
 * sendJsonGatewayRequest:
 * @self:       The pointer to json request object.
 * @gatewayUrl: The endpoint of SSO/Rest Gateway
 *
 * Send the json request ot specified g/w.
 */
void sendJsonGatewayRequest(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayRequest* jsonRequest)
{
	CURLcode curl_result_code;
	// long curl_http_code = 0;
	CurlContextRec *curl_context_rec = ssorest_pcalloc(r->pool, sizeof(*curl_context_rec));
	curl_context_rec->pool = r->pool;
    CURL *curl = get_curl_session(r, conf);

    curl_easy_setopt(curl, CURLOPT_URL, conf->gatewayUrl);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(jsonRequest));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlRecvData);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, curl_context_rec);

    // Add Debugging Options
    if(conf->isTraceEnabled)
    {
        // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, trace_libcurl);
        // curl_easy_setopt(curl, CURLOPT_DEBUGDATA, r);
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);        
    }


    curl_result_code = curl_easy_perform(curl);
    if (curl_result_code != CURLE_OK)
    {
        logError(r, "Failed to fetch url (%s) - curl reported: %s", conf->gatewayUrl, curl_easy_strerror(curl_result_code));
    }
    logError(r, "Received raw gateway response, length=%s", curl_context_rec->response_data);
}

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

        char *portwithcomma = ngx_pnalloc(r->pool, sizeof(":65535") - 1);
        ngx_sprintf((u_char *) portwithcomma, ":%ui", port);
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
                // TODO: Error Handling
            }

            if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
                    != NGX_OK)
            {
                // TODO: Error Handling
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
            // TODO: Error Handling
        }

        s.data = ngx_pnalloc(r->pool, s.len);
        if (s.data == NULL) {
            // TODO: Error Handling
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

static CURL* get_curl_session(SSORestRequestObject* r, SSORestPluginConfigration* conf)
{
	if ( conf->curl_session ) {

	} else {
		conf->curl_session = curl_easy_init();
		if ( conf->curl_session ) {
            #ifdef APACHE
			    apr_pool_cleanup_register(conf->cf_pool, conf->curl_session, (void *)curl_easy_cleanup, apr_pool_cleanup_null);
            #elif NGINX
                ngx_pool_cleanup_t  *cln;
                
                cln = ngx_pool_cleanup_add(conf->cf_pool, 0);
                if (cln == NULL) 
                {
                    // TODO: Error Handling
                }
                
                cln->handler = ssorest_curl_easy_cleanup;
                cln->data = conf->curl_session;
            #endif

            curl_easy_setopt(conf->curl_session, CURLOPT_TIMEOUT, 30);
            curl_easy_setopt(conf->curl_session, CURLOPT_FOLLOWLOCATION, 1);
            curl_easy_setopt(conf->curl_session, CURLOPT_SSL_VERIFYPEER, FALSE);
            curl_easy_setopt(conf->curl_session, CURLOPT_USERAGENT, "libcurl-agent/1.0");

            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, "Accept: application/json");
            headers = curl_slist_append(headers, "Content-Type: application/json");

			if ( headers ) {
                #ifdef APACHE
				    apr_pool_cleanup_register(r->server->process->pool, headers, (void *) curl_slist_free_all, apr_pool_cleanup_null);
                #elif NGINX
                    ngx_pool_cleanup_t  *cln;
                    
                    cln = ngx_pool_cleanup_add(conf->cf_pool, 0);
                    if (cln == NULL) 
                    {
                        // TODO: Error Handling
                    }
                    
                    cln->handler = ssorest_curl_slist_free_all;
                    cln->data = headers;
                #endif

                curl_easy_setopt(conf->curl_session, CURLOPT_HTTPHEADER, headers);
			}
		}
	}
	if ( conf->curl_session == NULL ) {
		// TODO: Error Handling
	}
	return conf->curl_session;
}
