#include "JsonGatewayResponse.h"

int parseJsonGatewayResponse(SSORestRequestObject *r, SSORestPluginConfigration *conf, const char* jsonString, JSonGatewayResponse* jsonGatewayResponse)
{
    if (jsonString == NULL)
    {
        logError(r, "Could not parse because of empty json string");
        jsonGatewayResponse = NULL;
        return 500;
    }
    if (jsonGatewayResponse == NULL)
        jsonGatewayResponse = ssorest_pcalloc(r->pool, sizeof(JSonGatewayResponse));
    
    enum json_tokener_error jerr = json_tokener_success;
    jsonGatewayResponse->json = json_tokener_parse_verbose(jsonString, &jerr);
    if (jsonGatewayResponse->json == NULL) {
        logError(r, "Failed to parse gateway response, error= %s", json_tokener_error_desc(jerr));
        return 500;
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

    return 0;
}
