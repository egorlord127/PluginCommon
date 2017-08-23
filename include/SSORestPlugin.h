#pragma once

#include "Global.h"
typedef struct SSORestPlugin SSORestPlugin;
typedef struct SSORestPluginConfigration SSORestPluginConfigration;

#ifdef APACHE
typedef apr_pool_t SSORestPluginPool;
#elif NGINX
typedef ngx_pool_t SSORestPluginPool;
#endif

struct SSORestPlugin
{
    SSORestPluginConfigration* pluginConfiguration;
    void (*createPluginConfiguration)(SSORestPlugin*, SSORestPluginPool*);

};
void* (*ssorest_pcalloc)(SSORestPluginPool*, size_t);
void* (*ssorest_palloc)(SSORestPluginPool*, size_t);
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

