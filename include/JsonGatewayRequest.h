#pragma once

#include <json-c/json.h>
#include "Global.h"

JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject*);
void sendJsonGatewayRequest(const char*);
void setJsonGatewayRequestAttributes(JSonGatewayRequest* , const char*, const char*);
