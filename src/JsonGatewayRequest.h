#pragma once

#include "Global.h"
#include "SSORestPlugin.h"
JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject*, SSORestPluginConfigration*);
char* sendJsonGatewayRequest(SSORestRequestObject*, SSORestPluginConfigration*,  JSonGatewayRequest*);
void setJsonGatewayRequestAttributes(JSonGatewayRequest* , const char*, const char*);

