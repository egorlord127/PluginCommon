#include "SSORestPlugin.h"
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_optional.h"


void createPluginConfiguration(SSORestPlugin* self, SSORestPluginPool* pool)
{
    self->pluginConfiguration = ssorest_pcalloc(pool, sizeof(SSORestPluginConfigration));
}

