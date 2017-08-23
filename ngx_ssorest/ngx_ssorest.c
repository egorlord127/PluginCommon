#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "SSORestPlugin.h"
static SSORestPlugin ssorest;

static void *createServerConfiguration(ngx_conf_t *cf);
static const char *setSSORestEnable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestTrace(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestUseServerNameAsDefault(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestSendFormParameters(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestACOName(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestGatewayUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestLocalContent(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestPluginId(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestSecretKey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestSSOZone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestIgnoreExt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static const char *setSSORestIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t moduleDirectives[] = {
        {
        ngx_string("SSORestEnabled"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestEnable,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestTrace"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestTrace,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestUseServerNameAsDefault"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestUseServerNameAsDefault,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestSendFormParameters"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                setSSORestSendFormParameters,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestACOName"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestACOName,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestGatewayUrl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestGatewayUrl,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestLocalContent"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestLocalContent,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestPluginId"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestPluginId,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestSecretKey"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                setSSORestSecretKey,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestSSOZone"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                setSSORestSSOZone,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestIgnoreExt"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                setSSORestIgnoreExt,
                0,
                0,
                NULL
        },
        {
        ngx_string("SSORestIgnoreUrl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_ANY,
                setSSORestIgnoreUrl,
                0,
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
        NULL,

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
    ssorest.createPluginConfiguration = createPluginConfiguration;
    ssorest.createPluginConfiguration(&ssorest, cf->pool);
    return ssorest.pluginConfiguration;
}

static const char *setSSORestEnable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    if (!strcasecmp(value[1].data, "on"))
        ssorest.pluginConfiguration->isEnabled = 1;
    return NGX_CONF_OK;
}
static const char *setSSORestTrace(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    if (!strcasecmp(value[1].data, "on"))
        ssorest.pluginConfiguration->isTraceEnabled = 1;
    return NGX_CONF_OK;
}
// static const char *setSSORestUseServerNameAsDefault(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestSendFormParameters(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestACOName(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestGatewayUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestLocalContent(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestPluginId(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestSecretKey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestSSOZone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestIgnoreExt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static const char *setSSORestIgnoreUrl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);