#pragma once
#include "Global.h"

typedef struct SSORestPlugin SSORestPlugin;
typedef struct SSORestPluginConfigration SSORestPluginConfigration;

#ifdef APACHE
    typedef apr_pool_t SSORestPluginPool;
    #define ssorest_pcalloc(pool, size) (apr_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (apr_palloc(pool, size))
#elif NGINX
    typedef ngx_pool_t SSORestPluginPool;
    #define ssorest_pcalloc(pool, size) (ngx_pcalloc(pool, size))
    #define ssorest_palloc(pool, size) (ngx_palloc(pool, size))
#endif

struct SSORestPlugin
{
    SSORestPluginConfigration* pluginConfiguration;
    void (*createPluginConfiguration)(SSORestPlugin*, SSORestPluginPool*);

};
// void* (*ssorest_pcalloc)(SSORestPluginPool*, size_t);
// void* (*ssorest_palloc)(SSORestPluginPool*, size_t);
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

