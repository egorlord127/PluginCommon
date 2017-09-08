#pragma once
#include "Global.h"
// #include "JsonGatewayResponse.h"
#include <json-c/json.h>
#include <curl/curl.h>
typedef struct 
{
    int isEnabled;
    int isTraceEnabled;
    int useServerNameAsDefault;
    int sendFormParameters;
    int isDebugEnabled;
    const char *acoName;
    const char *gatewayUrl;
    const char *localrootpath;
    const char *pluginId;
    const char *secretKey;
    char *gatewayToken;
    ssorest_array_t *ssoZone;
    ssorest_array_t *ignoreExt;
    ssorest_array_t *ignoreUrl;
    CURL *curl_session;
    SSORestPluginPool *cf_pool;
} SSORestPluginConfigration;

typedef struct JSonGatewayResponse{
    json_object *json;
    json_object *jsonRequest;
    json_object *jsonRequestHeader;
    json_object *jsonRequestCookies;
    json_object *jsonResponse;
    json_object *jsonResponseBody;
    json_object *jsonResponseHeader;
    json_object *jsonResponseCookies;
    int status;
} JSonGatewayResponse;

typedef json_object JSonGatewayRequest;

SSORestPluginConfigration* createPluginConfiguration(SSORestPluginPool*);
int processRequest(SSORestRequestObject *request, SSORestPluginConfigration *conf);
int processJsonPayload(SSORestRequestObject *request, SSORestPluginConfigration *conf, JSonGatewayRequest *jsonGatewayRequest);
void setGatewayToken(SSORestRequestObject *request, SSORestPluginConfigration *conf, JSonGatewayResponse *res);
int parseJsonGatewayResponse(SSORestRequestObject *r, SSORestPluginConfigration *conf, const char* jsonString, JSonGatewayResponse **res);
int handleSignatureRequired(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayRequest *jsonGatewayRequest,JSonGatewayResponse *jsonGatewayResponse);
int handleAllowContinue(SSORestRequestObject* r, SSORestPluginConfigration* conf, JSonGatewayResponse *jsonGatewayResponse);
int propagateHeader(SSORestRequestObject *r, SSORestPluginConfigration* conf, json_object *, int dir);
int propagateCookies(SSORestRequestObject *r, SSORestPluginConfigration* conf, json_object *, int dir);
int transferContent(SSORestRequestObject *r, SSORestPluginConfigration* conf, json_object *);
