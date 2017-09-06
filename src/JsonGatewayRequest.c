#include "Global.h"
#include "JsonGatewayRequest.h"
#include "CurlWrapper.h"
#include "SSORestPlugin.h"
#include "Util.h"
#include "RequestInfo.h"

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
 * @r:           The pointer to request object.
 * @conf:        The pointer to plugin configuration.
 * @jsonRequest: The pointer to Json Reqeust object
 *
 * Send the json request ot specified g/w.
 *
 * Return string if curl is successfully done.
 * Return Null if it fails.
 */
char* sendJsonGatewayRequest(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayRequest* jsonRequest)
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
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, CurlTraceDebug);
        curl_easy_setopt(curl, CURLOPT_DEBUGDATA, r);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }

    curl_result_code = curl_easy_perform(curl);
    if (curl_result_code != CURLE_OK)
    {
        logError(r, "Failed to fetch url (%s) - curl reported: %s", conf->gatewayUrl, curl_easy_strerror(curl_result_code));
        return NULL;
    }

    return curl_context_rec->response_data;
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