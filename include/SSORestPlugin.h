#include "Global.h"
typedef struct SSORestPlugin SSORestPlugin;
typedef struct SSORestPluginConfigration SSORestPluginConfigration;
struct SSORestPlugin
{
    SSORestPluginConfigration* pluginConfiguration;
    void (*createPluginConfiguration)(SSORestPlugin*, apr_pool_t*);
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
void createPluginConfiguration(SSORestPlugin*, apr_pool_t*);
