#include "JsonGatewayResponse.h"

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

    // const char *pretty = json_object_to_json_string_ext(jsonGatewayResponse->json, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
    // logError(r, "Parsed reply from Gateway:");
    // int linenr = 0;
    // char *ptr, *temp = NULL;
    // ptr = strtok_r((char *) pretty, "\n", &temp);
    // while (ptr != NULL) {
    //     logError(r, "%3d: %s", ++linenr, ptr);
    //     ptr = strtok_r(NULL, "\n", &temp);
    // }

    json_object_object_get_ex(jsonGatewayResponse->json, "response", &jsonGatewayResponse->jsonResponse);
    json_object_object_get_ex(jsonGatewayResponse->json, "request", &jsonGatewayResponse->jsonRequest);

    json_object *jsonGatewayResponseStatus;
    json_object_object_get_ex(jsonGatewayResponse->jsonResponse, "status", &jsonGatewayResponseStatus);

    jsonGatewayResponse->status = json_object_get_int(jsonGatewayResponseStatus);
    logError(r, "TESTCODE:%d:%d", jsonGatewayResponse->status, sizeof(*jsonGatewayResponse));
    return SSOREST_OK;
}
