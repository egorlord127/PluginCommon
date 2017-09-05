#include "SSORestPlugin.h"
#include "JsonGatewayRequest.h"
#include "JsonGatewayResponse.h"

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
char* processRequest(SSORestRequestObject* r, SSORestPluginConfigration* conf)
{
    JSonGatewayRequest  *jsonGatewayRequest;
    JSonGatewayResponse *jsonGatewayResponse = NULL;
    jsonGatewayRequest = buildJsonGatewayRequest(r, conf);
    if (parseJsonGatewayResponse(r, conf, sendJsonGatewayRequest(r, conf, jsonGatewayRequest), &jsonGatewayResponse) == SSOREST_ERROR)
        return "Error";

    logError(r, "Gateway provided response status = %d", jsonGatewayResponse->status);
    if (jsonGatewayResponse->status == SC_NOT_EXTENDED)
    {
        const char *bodyContent = json_object_get_string(jsonGatewayResponse->jsonResponseBody);
        char *p = NULL;
        if (bodyContent)
            p = strstr(bodyContent, "Signature Needed");
        if (p)
        {
            // handleSignatureRequired();
        }
        else 
        {
            // handleSendLocalFile
        }

    }
    return "OK";
}
