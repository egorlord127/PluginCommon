#include "JsonGatewayRequest.h"
JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject* request)
{
    JSonGatewayRequest *jsonGatewayRequest = json_object_new_object();

    // method
    json_object_object_add(jsonGatewayRequest, "method", json_object_new_string(getMethod(request)));
    
    // url
    json_object_object_add(jsonGatewayRequest, "url", json_object_new_string(getUrl(request)));
    
    // protocol
    json_object_object_add(jsonGatewayRequest, "protocol", json_object_new_string(getProtocol(request)));

    // characterEncoding
    json_object_object_add(jsonGatewayRequest, "characterEncoding", json_object_new_string(getCharacterEncoding(request)));

    // contentLength
    json_object_object_add(jsonGatewayRequest, "contentLength", json_object_new_int(getContentLength(request)));

    // contentType
    json_object_object_add(jsonGatewayRequest, "contentType", json_object_new_string(getContentType(request)));

    // contextPath
    json_object_object_add(jsonGatewayRequest, "contextPath", json_object_new_string(getContextPath(request)));

    // localAddr
    json_object_object_add(jsonGatewayRequest, "localAddr", json_object_new_string(getLocalAddr(request)));

    // localName
    json_object_object_add(jsonGatewayRequest, "localName", json_object_new_string(getLocalName(request)));

    // localPort
    json_object_object_add(jsonGatewayRequest, "localPort", json_object_new_int(getLocalPort(request)));

    // remoteAddr
    json_object_object_add(jsonGatewayRequest, "remoteAddr", json_object_new_string(getRemoteAddr(request)));

    // remoteHost
    json_object_object_add(jsonGatewayRequest, "remoteHost", json_object_new_string(getRemoteHost(request)));

    // remotePort
    json_object_object_add(jsonGatewayRequest, "remotePort", json_object_new_int(getRemotePort(request)));

    // secure
    json_object_object_add(jsonGatewayRequest, "secure", json_object_new_boolean(getSecure(request)));

    // scheme
    json_object_object_add(jsonGatewayRequest, "scheme", json_object_new_string(getScheme(request)));

    // serverName
    json_object_object_add(jsonGatewayRequest, "serverName", json_object_new_string(getServerName(request)));

    // serverPort
    json_object_object_add(jsonGatewayRequest, "serverPort", json_object_new_int(getServerPort(request)));

    // servletPath
    json_object_object_add(jsonGatewayRequest, "servletPath", json_object_new_string(""));

    // // locales
    // json_object_object_add(jsonGatewayRequest, "locales", json_object_new_string(""));

    // // headers
    // json_object* jsonGatewayRequestHeaders = json_object_new_object();
    
    // // headers: accept-language
    // json_object_object_add(jsonGatewayRequestHeaders, "accept-language", json_object_new_string(""));

    // // headers: connection
    // json_object_object_add(jsonGatewayRequestHeaders, "connection", json_object_new_string(""));

    // // headers: accept
    // json_object_object_add(jsonGatewayRequestHeaders, "accept", json_object_new_string(""));

    // // headers: host
    // json_object_object_add(jsonGatewayRequestHeaders, "host", json_object_new_string(""));

    // // headers: accept-encoding
    // json_object_object_add(jsonGatewayRequestHeaders, "accept-encoding", json_object_new_string(""));

    // // headers: user-agent
    // json_object_object_add(jsonGatewayRequestHeaders, "user-agent", json_object_new_string(""));

    // // headers
    // json_object_object_add(jsonGatewayRequest, "headers", jsonGatewayRequestHeaders);

    // // cookies
    
    // // parameters

    // // attributes
    return jsonGatewayRequest;
}

void setJsonGatewayRequestAttributes(JSonGatewayRequest* self, const char* key, const char* value)
{
    
}

void sendJsonGatewayRequest(const char* gatewayUrl)
{
    
}

const char* getMethod(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->method? r->method : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getUrl(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->uri? r->uri : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getUri(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->uri? r->uri : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getProtocol(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    if (r->main)
        rv = r->main->protocol;
    else
        rv = r->protocol;
    #elif NGINX

    #endif

    return rv;
}
const char* getCharacterEncoding(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->content_encoding? r->content_encoding : "";
    #elif NGINX

    #endif

    return rv;
}
int getContentLength(SSORestRequestObject* r)
{
    int rv; 
    #ifdef APACHE
    rv = r->clength? r->clength : 0;
    #elif NGINX

    #endif

    return rv;
}
const char* getContentType(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->content_type? r->content_type : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getContextPath(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = ap_document_root(r);
    #elif NGINX

    #endif

    return rv;
}
const char* getLocalAddr(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->connection->local_ip? r->connection->local_ip : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getLocalName(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->server->server_hostname? r->server->server_hostname : "";
    #elif NGINX

    #endif

    return rv;
}
int getLocalPort(SSORestRequestObject* r)
{
    int rv = 0;
    #ifdef APACHE
    rv = r->server->port;
    if (rv == 0)
    {
        if (r->server->addrs)
            rv = r->server->addrs->host_port;
    }
    #elif NGINX

    #endif

    return rv;
}
const char* getRemoteAddr(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->useragent_ip? r->useragent_ip : "";
    #elif NGINX

    #endif

    return rv;
}
const char* getRemoteHost(SSORestRequestObject* r)
{
    const char* rv; 
    #ifdef APACHE
    rv = r->useragent_ip? r->useragent_ip : "";
    #elif NGINX

    #endif

    return rv;
}
int getRemotePort(SSORestRequestObject* r)
{
    int rv = 0;
    #ifdef APACHE
    rv = r->useragent_addr->port? r->useragent_addr->port : 0;
    #elif NGINX

    #endif

    return rv;
}
int getSecure(SSORestRequestObject* r)
{
    int rv = 0;
    const char* scheme = getScheme(r);
    if(!strcasecmp(scheme, "https"))
        rv = 1;
    return rv;
}
const char* getScheme(SSORestRequestObject* r)
{
    int port = getServerPort(r);
    switch (port)
    {
        case 80: 
            return "http";
        case 443: 
            return "https";
        default: 
            return "";
    }
}
const char* getServerName(SSORestRequestObject* r)
{
    const char* rv;
    #ifdef APACHE
    rv = r->server->server_hostname? r->server->server_hostname : "";
    #elif NGINX

    #endif

    return rv;
}
int getServerPort(SSORestRequestObject* r)
{
    int rv = 0;
    #ifdef APACHE
    rv = r->server->port;
    if (rv == 0)
    {
        if (r->server->addrs)
            rv = r->server->addrs->host_port;
    }
    #elif NGINX

    #endif

    return rv;
}
// const char* getLocales(SSORestRequestObject* r)
// {
    
// }
// const char* getAcceptLanguage(SSORestRequestObject* r)
// {
    
// }
// const char* getConnection(SSORestRequestObject* r)
// {
    
// }
// const char* getAccept(SSORestRequestObject* r)
// {
    
// }
// const char* getHost(SSORestRequestObject* r)
// {
    
// }
// const char* getAcceptEncoding(SSORestRequestObject* r)
// {
    
// }
// const char* getUserAgent(SSORestRequestObject* r)
// {
    
// }