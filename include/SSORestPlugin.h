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
    const char* acoName;
    const char* gatewayUrl;
    const char* localrootpath;
    const char* pluginId;
    const char* secretKey;
    const char* gatewayToken;
    const char* ssoZone;
    const char* ignoreExt;
    const char* ignoreUrl;
};

void createPluginConfiguration(SSORestPlugin*, SSORestPluginPool*);
char* processRequest(SSORestRequestObject* request, SSORestPlugin* plugin);
