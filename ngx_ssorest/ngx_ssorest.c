#include "Global.h"
#include "SSORestPlugin.h"

static ngx_int_t ngx_ssorest_plugin_init(ngx_conf_t *cf);
static ngx_int_t ngx_ssorest_plugin_request_handler(ngx_http_request_t *r);

static void *createServerConfiguration(ngx_conf_t *cf);
static char *setSSORestEnable(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestTrace(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestUseServerNameAsDefault(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestSendFormParameters(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestACOName(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestGatewayUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestLocalContent(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestPluginId(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestSecretKey(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestSSOZone(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestIgnoreExt(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);
static char *setSSORestIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg);

static ngx_command_t moduleDirectives[] = {
        {
        ngx_string("SSORestEnabled"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestEnable,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestTrace"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestTrace,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestUseServerNameAsDefault"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestUseServerNameAsDefault,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestSendFormParameters"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestSendFormParameters,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestACOName"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestACOName,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestGatewayUrl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestGatewayUrl,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestLocalContent"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestLocalContent,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestPluginId"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestPluginId,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestSecretKey"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestSecretKey,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestSSOZone"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                setSSORestSSOZone,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestIgnoreExt"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                setSSORestIgnoreExt,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },
        {
        ngx_string("SSORestIgnoreUrl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                setSSORestIgnoreUrl,
                NGX_HTTP_SRV_CONF_OFFSET,
                0,
                NULL
        },

        ngx_null_command
};

static ngx_http_module_t ngx_ssorest_plugin_module_ctx =
        {
        /* preconfiguration */
        NULL,

        /* postconfiguration */
        ngx_ssorest_plugin_init,

        /* create main configuration */
        NULL,

        /* init main configuration */
        NULL,

        /* create server configuration */
        createServerConfiguration,

        /* merge server configuration */
        NULL,

        /* create location configuration */
        NULL,

        /* merge location configuration */
        NULL
        // ngx_http_idfc_ssorest_merge_conf
        };

/* NGINX module definition. */
ngx_module_t ngx_ssorest_plugin_module =
        {
        NGX_MODULE_V1,
                &ngx_ssorest_plugin_module_ctx, /* module context */
                moduleDirectives, /* module directives */
                NGX_HTTP_MODULE, /* module teltsype */
                NULL, /* init master */
                NULL, /* init module */
                NULL, /* init process */
                NULL, /* init thread */
                NULL, /* exit thread */
                NULL, /* exit process */
                NULL, /* exit master */
                NGX_MODULE_V1_PADDING
        };

static void *createServerConfiguration(ngx_conf_t *cf)
{
    return createPluginConfiguration(cf->pool);
}

static char *setSSORestEnable(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    if (!ngx_strcasecmp(value[1].data, (u_char *) "on"))
        conf->isEnabled = 1;
    return NGX_CONF_OK;
}
static char *setSSORestTrace(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    if (!ngx_strcasecmp(value[1].data, (u_char *) "on"))
        conf->isTraceEnabled = 1;
    return NGX_CONF_OK;
}
static char *setSSORestUseServerNameAsDefault(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    if (!ngx_strcasecmp(value[1].data, (u_char *) "on"))
        conf->useServerNameAsDefault = 1;
    return NGX_CONF_OK;
}
static char *setSSORestSendFormParameters(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    if (!ngx_strcasecmp(value[1].data, (u_char *) "on"))
        conf->sendFormParameters = 1;
    return NGX_CONF_OK;
}
static char *setSSORestACOName(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    conf->acoName = (char *) value[1].data;
    return NGX_CONF_OK;
}
static char *setSSORestGatewayUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    conf->gatewayUrl = (char *) value[1].data;
    return NGX_CONF_OK;
}
static char *setSSORestLocalContent(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    conf->localrootpath = (char *) value[1].data;
    return NGX_CONF_OK;
}
static char *setSSORestPluginId(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    conf->pluginId = (char *) value[1].data;
    return NGX_CONF_OK;
}
static char *setSSORestSecretKey(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value = cf->args->elts;
    conf->secretKey = (char *) value[1].data;
    return NGX_CONF_OK;
}
static char *setSSORestSSOZone(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value;
    ngx_str_t *ssozone;
    ngx_uint_t i;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        ssozone = ngx_array_push(conf->ssoZone);
        if (ssozone == NULL)
            return NGX_CONF_ERROR ;
        *ssozone = value[i];
    }
    return NGX_CONF_OK;
}
static char *setSSORestIgnoreExt(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value;
    ngx_str_t *ignore;
    ngx_uint_t i;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].data[0] != '.' || value[i].len < 2) 
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "SSORestIgnoreExt should be start with '.'");

        ignore = ngx_array_push(conf->ignoreExt);
        if (ignore == NULL)
            return NGX_CONF_ERROR ;
        ignore->len = value[i].len - 1;
        ignore->data = value[i].data + 1;
    }
    return NGX_CONF_OK;
}
static char *setSSORestIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *cfg)
{
    SSORestPluginConfigration *conf = cfg;
    ngx_str_t *value;
    ngx_str_t *ignore;
    ngx_uint_t i;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        ignore = ngx_array_push(conf->ignoreUrl);
        if (ignore == NULL)
            return NGX_CONF_ERROR ;
        *ignore = value[i];
    }
    return NGX_CONF_OK;
}

/**
 * Initializes the SSO/Rest Plugin
 */
static ngx_int_t ngx_ssorest_plugin_init(ngx_conf_t *cf) 
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_ssorest_plugin_request_handler;

    // logNotice(cf->log, 0, "SSO/Rest Plugin initialized");

    #if defined(SVN_REV) && defined(MOD_VER)
        // logNotice(cf->log, 0, "SSO/Rest Plugin for NGINX v%s build %s", MOD_VER, SVN_REV);
    #endif

    return NGX_OK;
}

/**
 * Plugin runtime request processor
 */
static ngx_int_t ngx_ssorest_plugin_request_handler(ngx_http_request_t *r)
{
    SSORestPluginConfigration *conf = ngx_http_get_module_srv_conf(r, ngx_ssorest_plugin_module);
    return processRequest(r, conf, NULL);
}