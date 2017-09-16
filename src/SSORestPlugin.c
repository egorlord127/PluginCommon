/**
 * @file   SSORestPlugin.c
 * @author Egor Lord <elord@idfconnect.com>
 *
 */

#include "SSORestPlugin.h"
#include "JsonGatewayRequest.h"
#include "RequestInfo.h"
#include "Util.h"
#include "Logging.h"

/**
 * createPluginConfiguration
 * @pool: The pointer to plugin pool.
 *
 * Create configuration struct
 */
SSORestPluginConfigration* createPluginConfiguration(SSORestPluginPool* pool)
{
    SSORestPluginConfigration * conf = ssorest_pcalloc(pool, sizeof(SSORestPluginConfigration));

    conf->isEnabled              = SSOREST_CONF_UNSET;
    conf->isTraceEnabled         = SSOREST_CONF_UNSET;
    conf->useServerNameAsDefault = SSOREST_CONF_UNSET;
    conf->sendFormParameters     = SSOREST_CONF_UNSET;
    conf->isDebugEnabled         = SSOREST_CONF_UNSET;
    conf->acoName                = NULL;
    conf->gatewayUrl             = NULL;
    conf->localrootpath          = NULL;
    conf->pluginId               = NULL;
    conf->secretKey              = NULL;
    conf->gatewayToken           = NULL;
    conf->ssoZone                = NULL;
    conf->ignoreExt              = NULL;
    conf->ignoreUrl              = NULL;
    conf->ignoreHeaders          = NULL;
    
    #ifdef NGINX
        ngx_regex_compile_t rc;
        u_char              errstr[NGX_MAX_CONF_ERRSTR];
        ngx_str_t value = ngx_string("charset\\s*=\\s*([^\\s;]*)");

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = value;
        rc.pool = pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            return NULL;
        }

        conf->regex = rc.regex;
    #endif

    conf->cf_pool = pool;
    return conf;
}

#ifdef APACHE
SSORestPluginConfigration *mergePluginConfiguration(SSORestPluginPool *pool, void *parent, void *child)
#elif NGINX
char *mergePluginConfiguration(void *parent, void *child)
#endif
{
    SSORestPluginConfigration *prev = parent;
    SSORestPluginConfigration *conf = child;
    
    ssorest_conf_merge_value(conf->isEnabled, prev->isEnabled, 0);
    ssorest_conf_merge_value(conf->isTraceEnabled, prev->isTraceEnabled, 0);
    ssorest_conf_merge_value(conf->useServerNameAsDefault, prev->useServerNameAsDefault, 0);
    ssorest_conf_merge_value(conf->isDebugEnabled, prev->isDebugEnabled, 0);
    ssorest_conf_merge_value(conf->sendFormParameters, prev->sendFormParameters, 0);
    ssorest_conf_merge_ptr(conf->acoName, prev->acoName, NULL);
    ssorest_conf_merge_ptr(conf->gatewayUrl, prev->gatewayUrl, NULL);
    ssorest_conf_merge_ptr(conf->localrootpath, prev->localrootpath, NULL);
    ssorest_conf_merge_ptr(conf->pluginId, prev->pluginId, NULL);
    ssorest_conf_merge_ptr(conf->secretKey, prev->secretKey, NULL);
    ssorest_conf_merge_ptr(conf->ssoZone, prev->ssoZone, NULL);
    ssorest_conf_merge_ptr(conf->ignoreExt, prev->ignoreExt, NULL);
    ssorest_conf_merge_ptr(conf->ignoreUrl, prev->ignoreUrl, NULL);
    ssorest_conf_merge_ptr(conf->ignoreHeaders, prev->ignoreHeaders, NULL);
    
    #ifdef APACHE
        return conf;
    #elif NGINX
        return NULL;
    #endif
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
    if ( conf->isEnabled == SSOREST_CONF_DISABLED || conf->isEnabled == SSOREST_CONF_UNSET) 
    {
        if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
            logDebug(r, "SSO/Rest Plugin is disabled");
        return SSOREST_DECLINED;
    }
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
        logDebug(r, "Processing new request:%s", getUrl(r));

    // Do nothing if the uri match with ignore extension
    const char *requestExt = getRequestFileExtension(r);
    UINT i;
    if (conf->ignoreExt != NULL && conf->ignoreExt->nelts)
    {
        for (i = 0; i < conf->ignoreExt->nelts; i++ )
        {
            #ifdef APACHE
                const char *s = ((const char**)conf->ignoreExt->elts)[i];
            #elif NGINX
                const char *s = (const char *) ((ngx_str_t *)conf->ignoreExt->elts)[i].data;
            #endif
            if (strcmp(s, requestExt) == 0) {
                if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
                    logDebug(r, "Ignore Extension Matched");
                return SSOREST_DECLINED;
            }
        }
    }

    // Do nothing if the uri match with ignore url
    const char *uri = getUri(r);
    if (conf->ignoreUrl != NULL && conf->ignoreUrl->nelts)
    {
        for (i = 0; i < conf->ignoreUrl->nelts; i++ )
        {
            #ifdef APACHE
                const char *ignoreuri = ((const char**)conf->ignoreUrl->elts)[i];
            #elif NGINX
                const char *ignoreuri = (const char *) ((ngx_str_t *)conf->ignoreUrl->elts)[i].data;
            #endif
            if (strstr(uri, ignoreuri)) {
                if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
                    logDebug(r, "Ignore Url Matched");
                return SSOREST_DECLINED;
            }
        }
    }

    // Check if the gatewayUrl is configured
    if (conf->gatewayUrl == NULL)
    {
        logError(r, "No SSORestGatewayUrl in configuration");
        return SSOREST_INTERNAL_ERROR;
    }

    // Process the request
    int ret = processJsonPayload(r, conf, NULL);
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
        logDebug(r, "Request to Gateway had result code: %d", ret);
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

    // Constrcut Json Request to be sent to gateway.
    if (json == NULL)
    {
        jsonGatewayRequest = buildJsonGatewayRequest(r, conf);
    } 
    else 
    {
        jsonGatewayRequest = json;
    }
    
    JSonGatewayResponse *jsonGatewayResponse = NULL;

    // Parse Json Response from gateway.
    if (parseJsonGatewayResponse(r, conf, sendJsonGatewayRequest(r, conf, jsonGatewayRequest), &jsonGatewayResponse) == SSOREST_ERROR)
        return SSOREST_INTERNAL_ERROR;

    // Register cleanup function.
    #ifdef APACHE
        apr_pool_cleanup_register(r->pool, jsonGatewayResponse->json, (void *) json_object_put, apr_pool_cleanup_null);
    #elif NGINX
        ngx_pool_cleanup_t  *cln;
        
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) 
        {
            logError(r, "Failed to register cleanup function");
        }
        
        cln->handler = ssorest_json_cleanup;
        cln->data = jsonGatewayResponse->json;
    #endif

    if (conf->isEnabled)
        logError(r, "Gateway provided response status = %d", jsonGatewayResponse->status);

    // Remember the gateway token
    setGatewayToken(r, conf, jsonGatewayResponse);

    // If gateway reply with error, return internal server error.
    if (jsonGatewayResponse->status == SSOREST_BAD_GATEWAY || jsonGatewayResponse->status == SSOREST_INTERNAL_ERROR) {
        return SSOREST_INTERNAL_ERROR;
    }

    // Handle response SC_NOT_EXTENDED
    if (jsonGatewayResponse->status == SSOREST_SC_NOT_EXTENDED)
    {
        if (jsonGatewayResponse->jsonResponseBody == NULL || !json_object_is_type(jsonGatewayResponse->jsonResponseBody, json_type_string))
        {
            logError(r, "Could not get string from gateway response body");
            return SSOREST_INTERNAL_ERROR;
        }
        const char *bodyContent = json_object_get_string(jsonGatewayResponse->jsonResponseBody);
        char *p = NULL;
        if (bodyContent && conf->isDebugEnabled)
            p = strstr(bodyContent, "Signature Needed");
        if (p)
        {
            if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
                logDebug(r, "Signature is required for further talking");
            return handleSignatureRequired(r, conf, jsonGatewayRequest, jsonGatewayResponse);
        }
        else 
        {
            return handleSendLocalFile(r, conf, jsonGatewayRequest);
        }
    }

    // If the request is allowed to continue, progate headers and cookies from gateway.
    if (jsonGatewayResponse->status == SSOREST_SC_EXTENDED)
    {
        return handleAllowContinue(r, conf, jsonGatewayResponse);
    }

    // For all other response codes, send along back to the browser
    // Send Content-Type to the client
    if (jsonGatewayResponse->jsonResponseContentType != NULL && json_object_is_type(jsonGatewayResponse->jsonResponseContentType, json_type_string)) {
        const char* contentType = json_object_get_string(jsonGatewayResponse->jsonResponseContentType);
        #ifdef APACHE
            ap_set_content_type(r, contentType);
        #elif NGINX
            ngx_str_t str_tmp = ngx_string(contentType);
            r->headers_out.content_type = str_tmp;
        #endif
    }

    // Transfer response cookies
    if (propagateCookies(r, conf, jsonGatewayResponse->jsonResponseCookies, HEADERS_OUT) == SSOREST_OK && conf->isDebugEnabled)
    {
        logDebug(r, "Finished Transferring response cookies to the client");
    }
    
    // Transfer headers
    if (propagateHeader(r, conf, jsonGatewayResponse->jsonResponseHeader, HEADERS_OUT) == SSOREST_OK)
    {
        logDebug(r, "Finished Transferring response headers to the client");
    }

    // Transfer content
    if (transferContent(r, conf, jsonGatewayResponse->jsonResponseBody) == SSOREST_OK)
    {
        logDebug(r, "Finished Transferring content to the client");
    }

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

    // Check whether gateway support new challenge model or not.
    if (jsonGatewayResponse->jsonResponseHeader != NULL && json_object_is_type(jsonGatewayResponse->jsonResponseHeader, json_type_object))
    {
        json_object_object_get_ex(jsonGatewayResponse->jsonResponseHeader, CHALLENGE_HEADER_NAME, &challenge);

        if (challenge && json_object_is_type(challenge, json_type_array))
        {
            if (json_object_array_length(challenge))
            {
                json_object *tmp = json_object_array_get_idx(challenge, 0);
                if (tmp && json_object_is_type(tmp, json_type_string))
                {
                    challengeValue = (char *) json_object_get_string(tmp);
                    if (challengeValue != NULL)
                        isChallengeModel = 1;
                }
            }
        }
    }
    if (isChallengeModel)
    {
        if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
            logDebug(r, "Gateway support new challenge model");
        
        const char *digest = computeRFC2104HMAC(r, challengeValue, conf->secretKey);
        if (digest == NULL)
        {
            logError(r, "Failed to generate hmac from challengeValue");
            return SSOREST_INTERNAL_ERROR;
        }
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_ATTR, challengeValue);
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_SIGNED_ATTR, escape_str(r->pool, digest));
    }
    else 
    {
        if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
            logDebug(r, "Gateway does not support new challenge model");
        
        char randomText[33];
        generateSecureRandomString(randomText, 32);
        const char *digest = computeRFC2104HMAC(r, randomText, conf->secretKey);
        
        if (randomText == NULL || digest == NULL)
        {
            logError(r, "Failed to generate hmac from randomText");
            return SSOREST_INTERNAL_ERROR;
        }
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_ATTR, randomText);
        setJsonGatewayRequestAttributes(jsonGatewayRequest, RANDOMTEXT_SIGNED_ATTR, escape_str(r->pool, digest));
    }
    return processJsonPayload(r, conf, jsonGatewayRequest);
}

int handleSendLocalFile(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayRequest *jsonGatewayRequest)
{
    char *value = ssorest_pstrcat(r->pool, conf->localrootpath, getFileContextPath(r), NULL);
    size_t len;
    fcc_fileinfo fcc_file;
    if (conf->isDebugEnabled && value != NULL)
        logDebug(r, "File is located in %s", value);
    #ifdef APACHE
        apr_file_t *file;
        apr_finfo_t finfo;
        apr_off_t offset;
        if (apr_file_open(&file, value, APR_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server, "Cannot open file %s", value);
            return SSOREST_INTERNAL_ERROR;
        }

        apr_file_info_get(&finfo, APR_FINFO_SIZE, file);
        fcc_file.mtime = apr_time_sec(finfo.mtime);
        len = (size_t) finfo.size;
        if (len == 0)
        {
            apr_file_close(file);
            return SSOREST_INTERNAL_ERROR;
        }
        if ((fcc_file.content = (char *) apr_palloc(r->pool, len + 1)) == NULL)
        {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server, "Cannot allocate memory");
            apr_file_close(file);
            return SSOREST_INTERNAL_ERROR;
        }
        offset = 0;
        apr_file_seek(file, APR_SET, &offset);
        if (apr_file_read(file, fcc_file.content, &len) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server, "Cannot read from file %s", value);
            apr_file_close(file);
            return SSOREST_INTERNAL_ERROR;
        }
        fcc_file.content[len] = '\0';
        apr_file_close(file);
    #elif NGINX
        ssize_t n;
        ngx_file_t file;
        ngx_str_t  filename;
        ngx_file_info_t fi;
        
        filename.data = (u_char *) value;
        filename.len = strlen(value);
        ngx_memzero(&file, sizeof(ngx_file_t));
        file.name = filename;
        file.log = r->connection->log;

        file.fd = ngx_open_file(filename.data, NGX_FILE_RDONLY, 0, 0);
        if (file.fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, ngx_open_file_n " \"%s\" failed", filename.data);
            return SSOREST_INTERNAL_ERROR;
        }

        if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, ngx_fd_info_n " \"%s\" failed", filename.data);
            return SSOREST_INTERNAL_ERROR;
        }

        len = (size_t) ngx_file_size(&fi);
        fcc_file.mtime = ngx_file_mtime(&fi);
        
        fcc_file.content = (char*) ngx_palloc(r->pool, len + 1);
        if (fcc_file.content == NULL) {
            return SSOREST_INTERNAL_ERROR;
        }
    
        n = ngx_read_file(&file, (u_char *) fcc_file.content, len, 0);
    
        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, ngx_read_file_n " \"%s\" failed", filename.data);
            return SSOREST_INTERNAL_ERROR;
        }
    
        // Add null terminate.
        fcc_file.content[len] = '\0';
    
        if ((size_t) n != len) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, ngx_read_file_n " \"%s\" returned only %z bytes instead of %z", filename.data, n, len);
            return SSOREST_INTERNAL_ERROR;
        }

        if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, ngx_close_file_n " \"%s\" failed", filename.data);
            return SSOREST_INTERNAL_ERROR;
        }
    #endif

    // Perform base64 Encode
    int encoded_len = ((len + 2) / 3) * 4;
    char *encodedContent = ssorest_pcalloc(r->pool, encoded_len);
    encoded_len = base64_encode((unsigned char *) fcc_file.content, (unsigned char *) encodedContent, len);
    encodedContent[encoded_len] = '\0';
    
    if (conf->isDebugEnabled && encodedContent != NULL)
    {
        logDebug(r, "File Content: %s", fcc_file.content);
        logDebug(r, "Base64 Encoded Content: %s", encodedContent);
        logDebug(r, "Modified time: %ld", fcc_file.mtime);
    }

    // Set Attributes
    json_object *atts_json;
    json_object_object_get_ex(jsonGatewayRequest, "attributes", &atts_json);
    json_object_object_add(atts_json, "content", json_object_new_string(encodedContent));
    json_object_object_add(atts_json, "contentTimestamp", json_object_new_int64(fcc_file.mtime));

    return processJsonPayload(r, conf, jsonGatewayRequest);
}

/**
 * handleAllowContinue
 * @r:                   The pointer to request object.
 * @conf:                The pointer to plugin configuration.
 * @jsonGatewayResponse: The pointer to plugin configuration.
 *
 * TODO: Function Details
 *
 * Return http status code depending on g/w response.
 */
int handleAllowContinue(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayResponse *jsonGatewayResponse)
{
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
        logDebug(r, "Entering handleAllowContinue");

    // Transfer request headers
    if (propagateHeader(r, conf, jsonGatewayResponse->jsonRequestHeader, HEADERS_IN) == SSOREST_OK && conf->isDebugEnabled)
    {
        logDebug(r, "Finished Transferring gateway headers to the request");
    }
    
    // Transfer request cookies
    if (propagateCookies(r, conf, jsonGatewayResponse->jsonRequestCookies, HEADERS_IN) == SSOREST_OK && conf->isDebugEnabled)
    {
        logDebug(r, "Finished Transferring gateway cookies to the request");
    }

    // Transfer any new cookies to the response
    if (propagateCookies(r, conf, jsonGatewayResponse->jsonResponseCookies, HEADERS_OUT) == SSOREST_OK && conf->isDebugEnabled)
    {
        logDebug(r, "Finished Transferring response cookies to the client");
    }

    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
        logDebug(r, "Exiting handleAllowContinue");
    return SSOREST_OK;
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

    // Debug Raw gateway response
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
    {
        logDebug(r, "Received raw gateway response:");
        logDebug(r, "%s", jsonString);
    }
        
    enum json_tokener_error jerr = json_tokener_success;
    jsonGatewayResponse->json = json_tokener_parse_verbose(jsonString, &jerr);
    if (jsonGatewayResponse->json == NULL || jerr != json_tokener_success) {
        logError(r, "Failed to parse gateway response, error= %s", json_tokener_error_desc(jerr));
        return SSOREST_ERROR;
    }

    // Debug Json Response
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
    {
        const char *pretty = json_object_to_json_string_ext(jsonGatewayResponse->json, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
        logDebug(r, "Parsed reply from Gateway:");    
        int linenr = 0;
        char *ptr, *temp = NULL;
        ptr = strtok_r((char * )pretty, "\n", &temp);
        while (ptr != NULL) {
            logDebug(r, "%2d: %s", ++linenr, ptr);
            ptr = strtok_r(NULL, "\n", &temp);
        }
    }
    
    // Get json object from json gateway response.
    // Note: no reference counts is changed using 'json_object_object_get_ex' function.
    json_object_object_get_ex(jsonGatewayResponse->json, "request", &jsonGatewayResponse->jsonRequest);
    json_object_object_get_ex(jsonGatewayResponse->jsonRequest, "headers", &jsonGatewayResponse->jsonRequestHeader);
    json_object_object_get_ex(jsonGatewayResponse->jsonRequest, "cookies", &jsonGatewayResponse->jsonRequestCookies);
    
    json_object_object_get_ex(jsonGatewayResponse->json, "response", &jsonGatewayResponse->jsonResponse);
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "body", &jsonGatewayResponse->jsonResponseBody);
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "headers", &jsonGatewayResponse->jsonResponseHeader);
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "cookies", &jsonGatewayResponse->jsonResponseCookies);
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "content-type", &jsonGatewayResponse->jsonResponseContentType);
    
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
    // Check if  gateway response header is not null
    if (jsonGatewayResponse->jsonResponseHeader == NULL || !json_object_is_type(jsonGatewayResponse->jsonRequestHeader, json_type_object))
        return;
    
    // Get gatewayToken from the gateway response.
    json_object *gatewayTokenJson = NULL;
    json_object_object_get_ex(jsonGatewayResponse->jsonResponseHeader, GATEWAY_TOKEN_NAME, &gatewayTokenJson);

    if (gatewayTokenJson == NULL || !json_object_is_type(gatewayTokenJson, json_type_array))
        return;

    if (!json_object_array_length(gatewayTokenJson))
        return;
    
    json_object *gatewayTokenValue = json_object_array_get_idx(gatewayTokenJson, 0);
    if (gatewayTokenValue == NULL || !json_object_is_type(gatewayTokenValue, json_type_string))
        return;

    // get gatewayToken string from gateway.
    const char* gatewayToken = json_object_get_string(gatewayTokenValue);
    int gatewayTokenLength = strlen(gatewayToken);

    // Store gatewayToken into configuration.
    conf->gatewayToken = ssorest_pcalloc(conf->cf_pool, gatewayTokenLength + 1);
    memcpy(conf->gatewayToken, (char *) gatewayToken, gatewayTokenLength);
    conf->gatewayToken[gatewayTokenLength] = '\0';
    
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
        logDebug(r, "Plugin stored gatwayToken=%s, len=%d", conf->gatewayToken, gatewayTokenLength);
}

int propagateHeader(SSORestRequestObject *r, SSORestPluginConfigration* conf, json_object *headers, int dir)
{
    if (dir != HEADERS_IN && dir != HEADERS_OUT)
    {
        logError(r, "Wrong Parameter: 'propagateHeader' only support HEADERS_IN or HEADERS_OUT");
        return SSOREST_WRONG_PARAMETER;
    }

    if (headers == NULL || !json_object_is_type(headers, json_type_object))
    {
        logError(r, "Could not found headers");
        return SSOREST_NOT_FOUND;
    }
    
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
    {
        const char *pretty = json_object_to_json_string_ext(headers, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
        if (dir == HEADERS_OUT)
            logDebug(r, "Transferring gateway request headers to client");    
        else 
            logDebug(r, "Transferring gateway request headers to request");

        int linenr = 0;
        char *ptr, *temp = NULL;
        ptr = strtok_r((char * )pretty, "\n", &temp);
        while (ptr != NULL) {
            logDebug(r, "%2d: %s", ++linenr, ptr);
            ptr = strtok_r(NULL, "\n", &temp);
        }
    }

    json_object_object_foreach(headers, key, jsonVal) {
        if (!strcasecmp(key, "cookie") || !strcasecmp(key, GATEWAY_TOKEN_NAME))
            continue;

        if (jsonVal == NULL || !json_object_is_type(jsonVal, json_type_array))
            continue;

        if (!json_object_array_length(jsonVal))
            continue;
        
        json_object *header = json_object_array_get_idx(jsonVal, 0);
        if (header == NULL || !json_object_is_type(header, json_type_string))
            continue;
        
        const char *value = json_object_get_string(header);
        if (value == NULL)
            continue;
        
        if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
        {
            if (dir == HEADERS_OUT)
                logDebug(r, "Transferring gateway request header to client: %s=%s", key, value);    
            else 
                logDebug(r, "Transferring gateway request header to request: %s=%s", key, value);    
        }

        #ifdef APACHE
            if (dir == HEADERS_IN)
            {
                ssorest_table_set(r->headers_in, key, value);
            } else {
                ssorest_table_set(r->headers_out, key, value);
            }
        #elif NGINX
            if (dir == HEADERS_IN)
            {
                ssorest_table_set(&r->headers_in.headers, key, value);
            } else {
                ssorest_table_set(&r->headers_out.headers, key, value);
            }
        #endif
    }
    return SSOREST_OK;
}

int propagateCookies(SSORestRequestObject *r, SSORestPluginConfigration* conf, json_object *jsonCookies, int dir)
{
    if (dir != HEADERS_IN && dir != HEADERS_OUT)
    {
        logError(r, "Wrong Parameter: 'propagateCookies' only support HEADERS_IN or HEADERS_OUT");
        return SSOREST_WRONG_PARAMETER;
    }

    if (jsonCookies == NULL || !json_object_is_type(jsonCookies, json_type_array) || !json_object_array_length(jsonCookies))
    {
        logError(r, "Could not found gateway cookies");
        return SSOREST_NOT_FOUND;
    }
    
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
    {
        const char *pretty = json_object_to_json_string_ext(jsonCookies, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
        if (dir == HEADERS_IN)
            logDebug(r, "Transferring gateway cookies to request");
        else
            logDebug(r, "Transferring gateway cookies to response");
        
        int linenr = 0;
        char *ptr, *temp = NULL;
        ptr = strtok_r((char * )pretty, "\n", &temp);
        while (ptr != NULL) {
            logDebug(r, "%2d: %s", ++linenr, ptr);
            ptr = strtok_r(NULL, "\n", &temp);
        }
    }
    
    int arraylen = json_object_array_length(jsonCookies);
    int i;
    for (i = 0; i < arraylen; i++)
    {
        json_object *jsonCookie = json_object_array_get_idx(jsonCookies, i);
        if (jsonCookie == NULL || !json_object_is_type(jsonCookie, json_type_array))
            continue;
        if (!json_object_array_length(jsonCookie))
            continue;
        json_object_object_foreach(jsonCookie, key, jsonValue) {
            const char *cname = NULL;
            const char *cvalue = NULL;
            const char *cpath = NULL;
            const char *cdomain = NULL;
            
            if (jsonValue == NULL || !json_object_is_type(jsonValue, json_type_string))
                continue;
            const char *value = json_object_get_string(jsonValue);

            if (strncmp(key, "name", sizeof("name") - 1) == 0) {
                cname = value;
            } else if (strncmp(key, "value", sizeof("value") - 1) == 0) {
                cvalue = value;
            } else if (strncmp(key, "path", sizeof("path") - 1) == 0) {
                cpath = value;
            } else if (strncmp(key, "domain", sizeof("domain") - 1) == 0) {
                cdomain = value;
            }

            if (!cname || !cvalue)
                continue;

            if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
                logDebug(r, "Prcessing Gateway Cookie %s=%s", cname, cvalue);
            
            char *newCookie = NULL;
            if (dir ==  HEADERS_OUT)
            {
                newCookie = ssorest_pstrcat(r->pool, cname, "=", cvalue, "; domain=", cdomain, "; path=",cpath, NULL);
                if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
                    logDebug(r, "Sending gateway cookie to client: %s\n", newCookie);

                #ifdef APACHE
                    ssorest_table_set(r->headers_out, "Set-Cookie", newCookie);  
                #elif NGINX
                    ssorest_table_set(&r->headers_out.headers, "Set-Cookie", newCookie);
                #endif
            }
            else 
            {
                // Get existing cookie first
                const char *cookiestring = getCookies(r);
                newCookie = ssorest_pstrcat(r->pool, cname, "=", cvalue, "; ", cookiestring, NULL);
                if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
                    logDebug(r, "Sending gateway cookie to request: %s\n", newCookie);

                #ifdef APACHE
                    ssorest_table_set(r->headers_in, "Cookie", newCookie);  
                #elif NGINX
                    ssorest_table_set(&r->headers_in.headers, "Cookie", newCookie);
                #endif
            }
        }
    }
    return SSOREST_OK;
}

int transferContent(SSORestRequestObject *r, SSORestPluginConfigration* conf, json_object *jsonResponseBody)
{
    if (jsonResponseBody == NULL || !json_object_is_type(jsonResponseBody, json_type_string))
    {
        logDebug(r, "Could not found gateway response body");
        return SSOREST_ERROR;
    }

    const char* body = json_object_get_string(jsonResponseBody);
    if (body == NULL)
    {
        logError(r, "Could not get string from gateway response body");
        return SSOREST_ERROR;
    }

    // Base64 Decode first
    int len = strlen(body);
    int decoded_len = ((len + 3) / 4) * 3;
    char *decoded_body = ssorest_pcalloc(r->pool, decoded_len + 1);
    decoded_len = base64_decode((unsigned char *) body, (unsigned char *) decoded_body, len);
    decoded_body[decoded_len] = '\0';
    
    if (conf->isDebugEnabled == SSOREST_CONF_ENABLED)
        logDebug(r, "Decoded Response Body from gateway = %s", decoded_body);

    #ifdef APACHE
        r->clength = decoded_len;
        ap_send_http_header(r);
        ap_rprintf(r, "%s", decoded_body);
    #elif NGINX
        ngx_buf_t *b;
        ngx_chain_t *out;
        r->headers_out.content_length_n = decoded_len;
        ngx_int_t rc = ngx_http_send_header(r);

        if (rc != NGX_OK) {
            logError(r, "Problem setting content length header, rc=%s", rc);
            return rc;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } 

        out = ngx_alloc_chain_link(r->pool);

        out->buf = b;
        out->next = NULL;

        b->start = b->pos = (unsigned char *) decoded_body;
        b->end = b->last = (unsigned char *) decoded_body + decoded_len;
        b->memory = 1;
        b->last_buf = 1;

        rc = ngx_http_output_filter(r, out);
        if (rc != NGX_OK) {
            logError(r, "Problem writing response body, rc=%s", rc);
        }
        else {
            logError(r, "Finished writing response body");
        }
    #endif

    return SSOREST_OK;
}

#ifdef NGINX
void ssorest_table_set(ngx_list_t *header, const char *key, const char *value)
{
    // Search if the same name exists in the header
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_table_elt_t *ho = NULL;
    ngx_uint_t       i;
    ngx_uint_t       key_len = strlen(key);

    part = &header->part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (key_len != h[i].key.len || ngx_strcasecmp((u_char *) key, h[i].key.data) != 0) {
            continue;
        }
        ho = &h[i];
    }
    if (ho == NULL)
    {
        ho = ngx_list_push(header);
        if (ho == NULL)
        {
            // TODO: Error Handling
            // logError(r, "Failed to add new element into list");
        }
    }   
    ho->hash = 1;
    ho->key.len = strlen(key);
    ho->key.data = (u_char *) key;
    ho->value.len = strlen(value);
    ho->value.data = (u_char *) value;
}
#endif
