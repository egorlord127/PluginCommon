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
    parseJsonGatewayResponse(r, conf, sendJsonGatewayRequest(r, conf, jsonGatewayRequest), &jsonGatewayResponse);
    

    logError(r, "Gateway provided response status = %d", jsonGatewayResponse->status);
    return "OK";
    // if (jsonGatewayRequest == NULL)
    //     return "Null";
    // // return "Not Null";
    // char *ret = (char *) json_object_to_json_string_ext(jsonGatewayRequest, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
    // return ret;
    // sendJsonGatewayRequest(plugin->pluginConfiguration->gatewayUrl);
}
