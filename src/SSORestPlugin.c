#include "SSORestPlugin.h"
#include "JsonGatewayRequest.h"
#include "RequestInfo.h"
#include "Util.h"

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

int processRequest(SSORestRequestObject *r, SSORestPluginConfigration *conf, JSonGatewayResponse *jsonGatewayResponse)
{
    if (jsonGatewayResponse != NULL && jsonGatewayResponse->status == SSOREST_SC_EXTENDED)
    {
        logError(r, "Found gatewayResponse attribute in request");
        // TODO: handleAllowContinue
    }
    return processRequestInt(r, conf, jsonGatewayResponse);
}

int processRequestInt(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayResponse *jsonGatewayResponse)
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
    
    JSonGatewayRequest  *jsonGatewayRequest;
    if (jsonGatewayResponse == NULL || jsonGatewayResponse->jsonRequest == NULL)
    {
        jsonGatewayRequest = buildJsonGatewayRequest(r, conf);
    } 
    else 
    {
        jsonGatewayRequest = jsonGatewayResponse->jsonRequest;
    }

    if (parseJsonGatewayResponse(r, conf, sendJsonGatewayRequest(r, conf, jsonGatewayRequest), &jsonGatewayResponse) == SSOREST_ERROR)
        return SSOREST_INTERNAL_ERROR;

    logError(r, "Gateway provided response status = %d", jsonGatewayResponse->status);

    if (jsonGatewayResponse->status == SSOREST_SC_NOT_EXTENDED)
    {
        const char *bodyContent = json_object_get_string(jsonGatewayResponse->jsonResponseBody);
        char *p = NULL;
        if (bodyContent)
            p = strstr(bodyContent, "Signature Needed");
        if (p)
        {
            logError(r, "Signature is required for further talking");
            handleSignatureRequired(r, conf, jsonGatewayResponse);
        }
        else 
        {
            // handleSendLocalFile
        }

    }
    return SSOREST_OK;
}


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
    if (jsonGatewayResponse->json == NULL) {
        logError(r, "Failed to parse gateway response, error= %s", json_tokener_error_desc(jerr));
        return SSOREST_ERROR;
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


void handleSignatureRequired(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayResponse *jsonGatewayResponse)
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
        setJsonGatewayRequestAttributes(jsonGatewayResponse->jsonRequest, RANDOMTEXT_ATTR, challengeValue);
        setJsonGatewayRequestAttributes(jsonGatewayResponse->jsonRequest, RANDOMTEXT_SIGNED_ATTR, digest);
    }
    else 
    {
        char randomText[33];
        generateSecureRandomString(randomText, 32);
        const char *digest = computeRFC2104HMAC(r, randomText, conf->secretKey);
        setJsonGatewayRequestAttributes(jsonGatewayResponse->jsonRequest, RANDOMTEXT_ATTR, randomText);
        setJsonGatewayRequestAttributes(jsonGatewayResponse->jsonRequest, RANDOMTEXT_SIGNED_ATTR, digest);
    }
}

