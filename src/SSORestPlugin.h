#pragma once
#include "Global.h"
#include <json-c/json.h>
#include <curl/curl.h>
typedef struct 
{
    int isEnabled;
    int isTraceEnabled;
    int useServerNameAsDefault;
    int sendFormParameters;
    const char *acoName;
    const char *gatewayUrl;
    const char *localrootpath;
    const char *pluginId;
    const char *secretKey;
    const char *gatewayToken;
    ssorest_array_t *ssoZone;
    ssorest_array_t *ignoreExt;
    ssorest_array_t *ignoreUrl;
    CURL *curl_session;
    SSORestPluginPool *cf_pool;
} SSORestPluginConfigration;

typedef struct 
{
    SSORestPluginConfigration* pluginConfiguration;
} SSORestPlugin;



SSORestPluginConfigration* createPluginConfiguration(SSORestPluginPool*);
int processRequest(SSORestRequestObject* request, SSORestPluginConfigration* plugin);

typedef json_object JSonGatewayRequest;