#include "SSORestPlugin.h"
#include "JsonGatewayRequest.h"
#include "JsonGatewayResponse.h"

void createPluginConfiguration(SSORestPlugin* plugin, SSORestPluginPool* pool)
{
    plugin->pluginConfiguration = ssorest_pcalloc(pool, sizeof(SSORestPluginConfigration));
}
char* processRequest(SSORestRequestObject* request, SSORestPlugin* plugin)
{
    JSonGatewayRequest* jsonGatewayRequest;
    // setJsonGatewayRequestAttributes(&jsonGatewayRequest, "acoName", plugin->pluginConfiguration->acoName);
    // setJsonGatewayRequestAttributes(&jsonGatewayRequest, "pluginId", plugin->pluginConfiguration->pluginId);
    // setJsonGatewayRequestAttributes(&jsonGatewayRequest, "gatewayToken", plugin->pluginConfiguration->gatewayToken);
    
    // testcode for now
    ssorest_array_t *ssoZone;
    ssoZone = ssorest_array_create(request->pool, 1, sizeof(ssorest_str_t));
    ssorest_str_t *value = ssorest_array_push(ssoZone);
    value->len = 2;
    value->data = (u_char *) "SM";
    int sendFormParameters = 1;
    jsonGatewayRequest = buildJsonGatewayRequest(request, ssoZone, sendFormParameters);
    if (jsonGatewayRequest == NULL)
        return "Null";
    // return "Not Null";
    char *ret = (char *) json_object_to_json_string_ext(jsonGatewayRequest, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
    return ret;
    // sendJsonGatewayRequest(plugin->pluginConfiguration->gatewayUrl);
}
