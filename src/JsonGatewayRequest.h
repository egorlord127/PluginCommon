/**
 * @file   JsonGatewayRequest.h
 * @author Egor Lord <elord@idfconnect.com>
 *
 */

#pragma once

#include "Global.h"
#include "SSORestPlugin.h"
JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject*, SSORestPluginConfigration*);
char* sendJsonGatewayRequest(SSORestRequestObject*, SSORestPluginConfigration*,  JSonGatewayRequest*);
void setJsonGatewayRequestAttributes(JSonGatewayRequest* , const char*, const char*);
#ifdef NGINX
void ssorest_json_cleanup(void *data);
void ssorest_curl_easy_cleanup(void *data);
void ssorest_curl_slist_free_all(void *data);
#endif

