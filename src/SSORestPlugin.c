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
    
    jsonGatewayRequest = buildJsonGatewayRequest(request, plugin->pluginConfiguration);
    if (jsonGatewayRequest == NULL)
        return "Null";
    // return "Not Null";
    char *ret = (char *) json_object_to_json_string_ext(jsonGatewayRequest, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
    return ret;
    // sendJsonGatewayRequest(plugin->pluginConfiguration->gatewayUrl);
}
