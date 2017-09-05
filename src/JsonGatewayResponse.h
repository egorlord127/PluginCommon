#pragma once
#include <json-c/json.h>
#include "Global.h"
#include "SSORestPlugin.h"

typedef struct JSonGatewayResponse JSonGatewayResponse;
struct JSonGatewayResponse{
    json_object *json;
    json_object *jsonRequest;
    json_object *jsonResponse;
    json_object *jsonResponseHeader;
    json_object *jsonResponseCookies;
    int status;
};

int parseJsonGatewayResponse(SSORestRequestObject*, SSORestPluginConfigration*, const char*, JSonGatewayResponse**);
