#pragma once

#define APACHE

#ifdef APACHE
    #include <httpd.h>
#elif NGINX
    #include <ngx_config.h>
    #include <ngx_core.h>
#endif
