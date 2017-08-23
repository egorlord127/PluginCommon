#include "SSORestPlugin.h"
void createPluginConfiguration(SSORestPlugin* self, apr_pool_t* pool)
{
    self->pluginConfiguration = apr_pcalloc(pool, sizeof(SSORestPluginConfigration));
}