
struct SSORestPluginConfiguration
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