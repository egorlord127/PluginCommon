#include "SSORestPlugin.h"
#include "JsonGatewayRequest.h"
#include "RequestInfo.h"
#include "Util.h"

/**
 * createPluginConfiguration
 * @pool: The pointer to plugin pool.
 *
 * Create configuration struct
 */
SSORestPluginConfigration* createPluginConfiguration(SSORestPluginPool* pool)
{
    SSORestPluginConfigration * conf = ssorest_pcalloc(pool, sizeof(SSORestPluginConfigration));

    conf->isEnabled              = 0;
    conf->isTraceEnabled         = 0;
    conf->useServerNameAsDefault = 0;
    conf->sendFormParameters     = 0;
    conf->acoName                = NULL;
    conf->gatewayUrl             = NULL;
    conf->localrootpath          = NULL;
    conf->pluginId               = NULL;
    conf->secretKey              = NULL;
    conf->gatewayToken           = NULL;
    #ifdef APACHE
        conf->ssoZone            = ssorest_array_create(pool, 1, sizeof(const char *));
        conf->ignoreExt          = ssorest_array_create(pool, 1, sizeof(const char *));
        conf->ignoreUrl          = ssorest_array_create(pool, 1, sizeof(const char *));
    #elif NGINX
        conf->ssoZone            = ssorest_array_create(pool, 1, sizeof(ngx_str_t));
        conf->ignoreExt          = ssorest_array_create(pool, 1, sizeof(ngx_str_t));
        conf->ignoreUrl          = ssorest_array_create(pool, 1, sizeof(ngx_str_t));
    #endif
    conf->cf_pool = pool;
    return conf;
}

/**
 * processRequest
 * @r:           The pointer to request object.
 * @conf:        The pointer to plugin configuration.
 *
 * Interpret the request and evaluate it,
 *
 * Return http status code depending on g/w response.
 */
int processRequest(SSORestRequestObject *r, SSORestPluginConfigration *conf)
{
    if ( conf->isEnabled == 0) 
    {
        logError(r, "SSO/Rest Plugin is disabled");
        return SSOREST_DECLINED;
    }
    logError(r, "Processing new request:%s", getUrl(r));

    /* 1.Check if the request uri matches with ignored extension */
    const char *requestExt = getRequestFileExtension(r);
    UINT i;
    for (i = 0; i < conf->ignoreExt->nelts; i++ )
    {
        #ifdef APACHE
            const char *s = ((const char**)conf->ignoreExt->elts)[i];
        #elif NGINX
            const char *s = (const char *) ((ngx_str_t *)conf->ignoreExt->elts)[i].data;
        #endif
        if (strcmp(s, requestExt) == 0) {
            logError(r, "Ignore Extension Matched");
            return SSOREST_DECLINED;
        }
    }

    /* 2.Check if the request uri matches with ignored url */
    const char *uri = getUri(r);
    for (i = 0; i < conf->ignoreUrl->nelts; i++ )
    {
        #ifdef APACHE
            const char *ignoreuri = ((const char**)conf->ignoreUrl->elts)[i];
        #elif NGINX
            const char *ignoreuri = (const char *) ((ngx_str_t *)conf->ignoreUrl->elts)[i].data;
        #endif
        if (strstr(uri, ignoreuri)) {
            logError(r, "Ignore Url Matched");
            return SSOREST_DECLINED;
        }
    }

    int ret = processJsonPayload(r, conf, NULL);
    logError(r, "Request to Gateway had result code: %d", ret);
    return ret;
}

/**
 * processJsonPayload
 * @r:           The pointer to request object.
 * @conf:        The pointer to plugin configuration.
 * @json:        The pointer to json request
 *
 * Process the Json-based communication according to g/w result.
 *
 * Return http status code depending on g/w response.
 */
int processJsonPayload(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayRequest *json)
{
    JSonGatewayRequest  *jsonGatewayRequest;
    if (json == NULL)
    {
        jsonGatewayRequest = buildJsonGatewayRequest(r, conf);
    } 
    else 
    {
        jsonGatewayRequest = json;
    }
    
    JSonGatewayResponse *jsonGatewayResponse = NULL;

    if (parseJsonGatewayResponse(r, conf, sendJsonGatewayRequest(r, conf, jsonGatewayRequest), &jsonGatewayResponse) == SSOREST_ERROR)
        return SSOREST_INTERNAL_ERROR;

    #ifdef APACHE
        apr_pool_cleanup_register(r->pool, jsonGatewayResponse->json, (void *) json_object_put, apr_pool_cleanup_null);
    #elif NGINX
        ngx_pool_cleanup_t  *cln;
        
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) 
        {
            // TODO: Error Handling
        }
        
        cln->handler = ssorest_json_cleanup;
        cln->data = jsonGatewayResponse->json;
    #endif

    logError(r, "Gateway provided response status = %d", jsonGatewayResponse->status);

    // Remember the gateway token
    setGatewayToken(r, conf, jsonGatewayResponse);

    if (jsonGatewayResponse->status == SSOREST_BAD_GATEWAY || jsonGatewayResponse->status == SSOREST_INTERNAL_ERROR) {
        return SSOREST_INTERNAL_ERROR;
    }

    if (jsonGatewayResponse->status == SSOREST_SC_NOT_EXTENDED)
    {
        const char *bodyContent = json_object_get_string(jsonGatewayResponse->jsonResponseBody);
        char *p = NULL;
        if (bodyContent)
            p = strstr(bodyContent, "Signature Needed");
        if (p)
        {
            logError(r, "Signature is required for further talking");
            return handleSignatureRequired(r, conf, jsonGatewayRequest, jsonGatewayResponse);
        }
        else 
        {
            // handleSendLocalFile
        }
    }

    if (jsonGatewayResponse->status == SSOREST_SC_EXTENDED)
    {
        // TODO: handleAllowContinue
    }

    // Transfer response cookies
    if (jsonGatewayResponse->jsonResponseCookies)
    {
        json_object_object_foreach(jsonGatewayResponse->jsonResponseCookies, key, jsonVal)
        {
            logError(r, "Processing response cookie from JSon: %s", key);
            if (jsonVal == NULL)
                continue;
            
            json_object *cookieJson = json_object_array_get_idx(jsonVal, 0);

            if (cookieJson == NULL || !json_object_is_type(cookieJson, json_type_array))
                continue;

            char *cookieVal;
            const char *name = NULL;
            const char *value = NULL;
            const char *path = NULL;
            const char *domain = NULL;
            json_object_object_foreach(cookieJson, ckey, cval) {
                if (strncmp(ckey, "name", sizeof("name") - 1) == 0) {
                    name = json_object_get_string(cval);
                }
                else if (strncmp(ckey, "value", sizeof("value") - 1) == 0) {
                    value = json_object_get_string(cval);
                }
                else if (strncmp(ckey, "path", sizeof("path") - 1) == 0) {
                    path = json_object_get_string(cval);
                }
                else if (strncmp(ckey, "domain", sizeof("domain") - 1) == 0) {
                    domain = json_object_get_string(cval);
                }
            }

            cookieVal = ssorest_pstrcat(r->pool, name, "=", value, "; domain=", domain, "; path=", path);
            #ifdef APACHE
                apr_table_addn(r->headers_out, "Set-Cookie", cookieVal);
            #elif NGINX
                ngx_table_elt_t *cookie;
                cookie = ngx_list_push(&r->headers_out.headers);
                ngx_str_set(&cookie->key, "Set-Cookie");
                cookie->value.len = strlen(cookieVal);
                cookie->value.data = (u_char *) cookieVal;
            #endif

            logError(r, "Transferring header to response %s %s", key, value);
        }
    }
    
    // Transfer headers
    if (jsonGatewayResponse->jsonResponseHeader)
    {
        json_object_object_foreach(jsonGatewayResponse->jsonResponseHeader, key, jsonVal)
        {
            logError(r, "Processing response header from JSon: %s", key);
            if (strncmp(key, GATEWAY_TOKEN_NAME, strlen(GATEWAY_TOKEN_NAME)) == 0) // skip the gatewayToken
                continue;

            if (jsonVal == NULL)
                continue;
            
            json_object *jsonValue = json_object_array_get_idx(jsonVal, 0);

            if (jsonValue == NULL || !json_object_is_type(jsonValue, json_type_string))
                continue;

            char *value = (char *) json_object_get_string(jsonValue);
            
            #ifdef APACHE
                apr_table_set(r->headers_out, key, value);
            #elif NGINX
                ngx_table_elt_t *header;
                header   = ngx_list_push(&r->headers_out.headers);

                header->hash = 1;
                header->key.len = strlen(key);
                header->key.data = (u_char *) key;
                header->value.len = strlen(value);
                header->value.data = (u_char *) value;
            #endif
            logError(r, "Transferring header to response %s %s", key, value);
        }
    }

    // Transfer content

    return jsonGatewayResponse->status;
}

/**
 * handleSignatureRequired
 * @r:                      The pointer to request object.
 * @conf:                   The pointer to plugin configuration.
 * @jsonGatewayRequest:     The pointer to json request
 * @jsonGatewayResponse:    The pointer to json response struct
 *
 * It handles Signature
 * Handling signatuere is requried for the first time.
 * G/w support 2 kind of models regarding signature validation.
 *  - Challenge Model
 *     G/w send random string and module should send it back to g/w with hmac
 *  - Old Model 
 *     Module should send a pair of randomText and its hmac, they should be validated on g/w side.
 */
int handleSignatureRequired(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayRequest *jsonGatewayRequest,JSonGatewayResponse *jsonGatewayResponse)
{
    // Determine if g/w support new challenge model
    int isChallengeModel = 0;
    json_object *challenge = NULL;
    char *challengeValue = NULL;
    if (jsonGatewayResponse->jsonResponseHeader != NULL)
        json_object_object_get_ex(jsonGatewayResponse->jsonResponseHeader, CHALLENGE_HEADER_NAME, &challenge);

    if (challenge)
    {
        json_object *tmp = json_object_array_get_idx(challenge, 0);
        if (tmp)
            challengeValue = (char *) json_object_get_string(tmp);

        logError(r, "Gateway support new challenge model");
        isChallengeModel = 1;
    }
    else 
    {
        logError(r, "Gateway does not support new challenge model");
    }

    if (isChallengeModel)
    {
        const char *digest = computeRFC2104HMAC(r, challengeValue, conf->secretKey);
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_ATTR, challengeValue);
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_SIGNED_ATTR, escape_str(r->pool, digest));
    }
    else 
    {
        char randomText[33];
        generateSecureRandomString(randomText, 32);
        const char *digest = computeRFC2104HMAC(r, randomText, conf->secretKey);
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_ATTR, randomText);
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_SIGNED_ATTR, escape_str(r->pool, digest));
    }
    return processJsonPayload(r, conf, jsonGatewayRequest);
}

/**
 * parseJsonGatewayResponse
 * @r:                      The pointer to request object.
 * @conf:                   The pointer to plugin configuration.
 * @jsonString:             The json request string
 * @jsonGatewayResponse:    The pointer to json response struct
 *
 * Parse string into json object.
 * Parse @jsonString into @jsonGatewayResponse 
 *
 * Return Values
 * SSOREST_OK: means parsing is succeeded.
 * SSOREST_ERROR: means parsing is failed
 */
int parseJsonGatewayResponse(SSORestRequestObject *r, SSORestPluginConfigration *conf, const char* jsonString, JSonGatewayResponse **res)
{
    JSonGatewayResponse *jsonGatewayResponse = NULL;
    if (jsonString == NULL)
    {
        logError(r, "Could not parse because of empty json string");
        *res = NULL;
        return SSOREST_ERROR;
    }
    if (*res == NULL)
    {
        jsonGatewayResponse = ssorest_pcalloc(r->pool, sizeof(JSonGatewayResponse));
        *res= jsonGatewayResponse;
    }
    
    enum json_tokener_error jerr = json_tokener_success;
    jsonGatewayResponse->json = json_tokener_parse_verbose(jsonString, &jerr);
    if (jsonGatewayResponse->json == NULL || jerr != json_tokener_success) {
        logError(r, "Failed to parse gateway response, error= %s", json_tokener_error_desc(jerr));
        return SSOREST_ERROR;
    }
    
    const char *pretty = json_object_to_json_string_ext(jsonGatewayResponse->json, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
    logError(r, "Parsed reply from Gateway:");
    int linenr = 0;
    char *ptr, *temp = NULL;
    ptr = strtok_r((char *) pretty, "\n", &temp);
    while (ptr != NULL) {
        logError(r, "%3d: %s", ++linenr, ptr);
        ptr = strtok_r(NULL, "\n", &temp);
    }

    json_object_object_get_ex(jsonGatewayResponse->json, "response", &jsonGatewayResponse->jsonResponse);
    json_object_object_get_ex(jsonGatewayResponse->json, "request", &jsonGatewayResponse->jsonRequest);
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "body", &jsonGatewayResponse->jsonResponseBody);
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "headers", &jsonGatewayResponse->jsonResponseHeader);
    
    json_object *jsonGatewayResponseStatus;
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "status", &jsonGatewayResponseStatus);
    jsonGatewayResponse->status = json_object_get_int(jsonGatewayResponseStatus);
    
    return SSOREST_OK;
}

/**
 * setGatewayToken
 * @r:                      The pointer to request object.
 * @conf:                   The pointer to plugin configuration.
 * @jsonGatewayResponse:    The pointer to json response struct
 *
 * Store gatewayToken in configuration.
 *
 */
void setGatewayToken(SSORestRequestObject *r, SSORestPluginConfigration *conf, JSonGatewayResponse *jsonGatewayResponse)
{
    if (jsonGatewayResponse->jsonResponseHeader != NULL) {
        json_object *gwTokenJson = NULL;
        json_bool result = json_object_object_get_ex(jsonGatewayResponse->jsonResponseHeader, "gatewayToken", &gwTokenJson);
        if (result == TRUE && gwTokenJson != NULL) {
            json_object *gwTokenValue = NULL;
            if (json_object_array_length(gwTokenJson))
                gwTokenValue = json_object_array_get_idx(gwTokenJson, 0);

            if (gwTokenValue != NULL) {
                const char* gwToken = json_object_get_string(gwTokenValue);
                int gwTokenlen = strlen(gwToken);
                conf->gatewayToken = ssorest_pcalloc(conf->cf_pool, gwTokenlen + 1);
                memcpy(conf->gatewayToken, (char *) gwToken, gwTokenlen);
                conf->gatewayToken[gwTokenlen] = '\0';
                logError(r, "Plugin stored gatwayToken=%s, len=%d", conf->gatewayToken, gwTokenlen);
            }
        }
    }
}