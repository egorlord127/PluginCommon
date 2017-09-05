#pragma once
#include "Global.h"
#include <json-c/json.h>

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
} SSORestPluginConfigration;

typedef struct 
{
    SSORestPluginConfigration* pluginConfiguration;
} SSORestPlugin;



SSORestPluginConfigration* createPluginConfiguration(SSORestPluginPool*);
char* processRequest(SSORestRequestObject* request, SSORestPluginConfigration* plugin);

typedef json_object JSonGatewayRequest;