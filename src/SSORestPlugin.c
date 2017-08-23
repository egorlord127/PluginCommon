#include "SSORestPlugin.h"
#include <apr_pools.h>
void createPluginConfiguration(SSORestPlugin* self, SSORestPluginPool* pool)
{
    // self->pluginConfiguration = apr_pcalloc(pool, sizeof(SSORestPluginConfigration));
    ssorest_palloc = &apr_palloc;
    self->pluginConfiguration = ssorest_palloc(pool, sizeof(SSORestPluginConfigration));
}