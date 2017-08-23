#include <httpd.h>
#include <http_request.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_core.h>
#include <http_config.h>

#include "SSORestPlugin.h"

static SSORestPlugin ssorest;

static const char *setSSORestEnable(cmd_parms *cmd, void *cfg, const char* arg);
static const char *setSSORestTrace(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestUseServerNameAsDefault(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestSendFormParameters(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestACOName(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestGatewayUrl(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestLocalContent(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestPluginId(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestSecretKey(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestSSOZone(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestIgnoreExt(cmd_parms *cmd, void *cfg, const char *arg);
static const char *setSSORestIgnoreUrl(cmd_parms *cmd, void *cfg, const char *arg);
static int example_handler(request_rec *r);
static void register_hooks(apr_pool_t *pool);
static void *createServerConfiguration(apr_pool_t *p, server_rec *server);

static const command_rec moduleDirectives[] = 
{
    AP_INIT_TAKE1("SSORestEnabled", setSSORestEnable, NULL, OR_ALL, "Enable or disable mod_ssorest"),
    AP_INIT_TAKE1("SSORestTrace", setSSORestTrace, NULL, OR_ALL, "Enable or disable libcurl debug"),
    AP_INIT_TAKE1("SSORestUseServerNameAsDefault", setSSORestUseServerNameAsDefault, NULL, OR_ALL, ""),
    AP_INIT_TAKE1("SSORestSendFormParameters", setSSORestSendFormParameters, NULL, OR_ALL, ""),
    AP_INIT_TAKE1("SSORestACOName", setSSORestACOName, NULL, OR_ALL, ""),
    AP_INIT_TAKE1("SSORestGatewayUrl", setSSORestGatewayUrl, NULL, OR_ALL, "Gateway Location"),
    AP_INIT_TAKE1("SSORestLocalContent",setSSORestLocalContent, NULL, OR_ALL, "Gateway Location"),
    AP_INIT_TAKE1("SSORestPluginId", setSSORestPluginId, NULL, OR_ALL, ""),
    AP_INIT_TAKE1("SSORestSecretKey",setSSORestSecretKey, NULL, OR_ALL, ""),
    AP_INIT_ITERATE("SSORestSSOZone", setSSORestSSOZone, NULL, OR_ALL, ""),
    AP_INIT_ITERATE("SSORestIgnoreExt", setSSORestIgnoreExt, NULL, OR_ALL, ""),
    AP_INIT_ITERATE("SSORestIgnoreUrl", setSSORestIgnoreUrl, NULL, OR_ALL, ""),
    {NULL}
};

module AP_MODULE_DECLARE_DATA   ssorest_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    createServerConfiguration,
    NULL,
    moduleDirectives,
    register_hooks
};


static const char *setSSORestEnable(cmd_parms *cmd, void *cfg, const char *arg)
{
    if (!strcasecmp(arg, "on"))
        ssorest.pluginConfiguration->isEnabled = 1;
    return NULL;
}
static const char *setSSORestTrace(cmd_parms *cmd, void *cfg, const char *arg)
{
    if (!strcasecmp(arg, "on"))
        ssorest.pluginConfiguration->isTraceEnabled = 1;
    return NULL;
}
static const char *setSSORestUseServerNameAsDefault(cmd_parms *cmd, void *cfg, const char *arg)
{
    if (!strcasecmp(arg, "on"))
        ssorest.pluginConfiguration->useServerNameAsDefault = 1;
    return NULL;
}
static const char *setSSORestSendFormParameters(cmd_parms *cmd, void *cfg, const char *arg)
{
    if (!strcasecmp(arg, "on"))
        ssorest.pluginConfiguration->sendFormParameters = 1;
    return NULL;
}
static const char *setSSORestACOName(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->acoName = arg;
    return NULL;
}
static const char *setSSORestGatewayUrl(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->gatewayUrl = arg;
    return NULL;
}
static const char *setSSORestLocalContent(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->localrootpath = arg;
    return NULL;
}
static const char *setSSORestPluginId(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->pluginId = arg;
    return NULL;
}
static const char *setSSORestSecretKey(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->secretKey = arg;
    return NULL;
}
static const char *setSSORestSSOZone(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->ssoZone = arg;
    return NULL;
}
static const char *setSSORestIgnoreExt(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->ignoreExt = arg;
    return NULL;
}
static const char *setSSORestIgnoreUrl(cmd_parms *cmd, void *cfg, const char *arg)
{
    ssorest.pluginConfiguration->ignoreUrl = arg;
    return NULL;
}

static int process(request_rec *r)
{
    char *temp = processRequest(r, &ssorest);
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server, APLOGNO(10006)
                "testcode:%s", temp);
    return OK;
}

static void register_hooks(apr_pool_t *pool) 
{
    ap_hook_check_access(process, NULL, NULL, APR_HOOK_LAST, AP_AUTH_INTERNAL_PER_URI);
}

static void *createServerConfiguration(apr_pool_t *p, server_rec *server)
{
    createPluginConfiguration(&ssorest, p);
    return ssorest.pluginConfiguration;
}
