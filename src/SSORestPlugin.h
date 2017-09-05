#pragma once
#include "Global.h"

struct SSORestPlugin
{
    SSORestPluginConfigration* pluginConfiguration;
};

struct SSORestPluginConfigration
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
};

void createPluginConfiguration(SSORestPlugin*, SSORestPluginPool*);
char* processRequest(SSORestRequestObject* request, SSORestPlugin* plugin);
