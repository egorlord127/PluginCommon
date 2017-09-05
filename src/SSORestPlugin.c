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
    conf->ssoZone                = NULL;
    conf->ignoreExt              = NULL;
    conf->ignoreUrl              = NULL;
    
    return conf;
}
char* processRequest(SSORestRequestObject* request, SSORestPluginConfigration* conf)
{
    logEmerg(request, "isEnabled: %d", conf->isEnabled);
    logEmerg(request, "isTraceEnabled: %d", conf->isTraceEnabled);
    logEmerg(request, "useServerNameAsDefault: %d", conf->useServerNameAsDefault);
    logEmerg(request, "sendFormParameters: %d", conf->sendFormParameters);
    logEmerg(request, "acoName: %s", conf->acoName);
    logEmerg(request, "gatewayUrl: %s", conf->gatewayUrl);
    logEmerg(request, "localrootpath: %s", conf->localrootpath);
    logEmerg(request, "pluginId: %s", conf->pluginId);
    logEmerg(request, "secretKey: %s", conf->secretKey);

    UINT i;
    if (conf->ssoZone != NULL )
    {
        logEmerg(request, "ssoZone[%d]", conf->ssoZone->nelts);
        for (i = 0; i < conf->ssoZone->nelts; i++)
        {
            #ifdef APACHE
                const char *s = ((const char**)conf->ssoZone->elts)[i];
            #elif NGINX
                u_char *s = ((ngx_str_t *)conf->ssoZone->elts)[i].data;
            #endif
            logEmerg(request, "ssoZone[%d]: %s", i, s);
        }
    }

    if (conf->ignoreExt != NULL )
    {
        logEmerg(request, "ignoreExt[%d]", conf->ignoreExt->nelts);
        for (i = 0; i < conf->ignoreExt->nelts; i++)
        {
            #ifdef APACHE
                const char *s = ((const char**)conf->ignoreExt->elts)[i];
            #elif NGINX
                u_char *s = ((ngx_str_t *)conf->ignoreExt->elts)[i].data;
            #endif
            logEmerg(request, "ignoreExt[%d]: %s", i, s);
        }
    }

    if (conf->ignoreUrl != NULL )
    {
        logEmerg(request, "ignoreUrl[%d]", conf->ignoreUrl->nelts);
        for (i = 0; i < conf->ignoreUrl->nelts; i++)
        {
            #ifdef APACHE
                const char *s = ((const char**)conf->ignoreUrl->elts)[i];
            #elif NGINX
                u_char *s = ((ngx_str_t *)conf->ignoreUrl->elts)[i].data;
            #endif
            logEmerg(request, "ignoreUrl[%d]: %s", i, s);
        }
    }
    return "OK";
    
    // JSonGatewayRequest* jsonGatewayRequest;
    // // setJsonGatewayRequestAttributes(&jsonGatewayRequest, "acoName", plugin->pluginConfiguration->acoName);
    // // setJsonGatewayRequestAttributes(&jsonGatewayRequest, "pluginId", plugin->pluginConfiguration->pluginId);
    // // setJsonGatewayRequestAttributes(&jsonGatewayRequest, "gatewayToken", plugin->pluginConfiguration->gatewayToken);
    
    // jsonGatewayRequest = buildJsonGatewayRequest(request, plugin->pluginConfiguration);
    // if (jsonGatewayRequest == NULL)
    //     return "Null";
    // // return "Not Null";
    // char *ret = (char *) json_object_to_json_string_ext(jsonGatewayRequest, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
    // return ret;
    // sendJsonGatewayRequest(plugin->pluginConfiguration->gatewayUrl);
}
