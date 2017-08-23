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
    json_object_object_add(jsonGatewayRequest, "secure", json_object_new_string(""));

    // scheme
    json_object_object_add(jsonGatewayRequest, "scheme", json_object_new_string(""));

    // serverName
    json_object_object_add(jsonGatewayRequest, "serverName", json_object_new_string(""));

    // serverPort
    json_object_object_add(jsonGatewayRequest, "serverPort", json_object_new_int(0));

    // servletPath
    json_object_object_add(jsonGatewayRequest, "servletPath", json_object_new_string(""));

    // locales
    json_object_object_add(jsonGatewayRequest, "locales", json_object_new_string(""));

    // headers
    json_object* jsonGatewayRequestHeaders = json_object_new_object();
    
    // headers: accept-language
    json_object_object_add(jsonGatewayRequestHeaders, "accept-language", json_object_new_string(""));

    // headers: connection
    json_object_object_add(jsonGatewayRequestHeaders, "connection", json_object_new_string(""));

    // headers: accept
    json_object_object_add(jsonGatewayRequestHeaders, "accept", json_object_new_string(""));

    // headers: host
    json_object_object_add(jsonGatewayRequestHeaders, "host", json_object_new_string(""));

    // headers: accept-encoding
    json_object_object_add(jsonGatewayRequestHeaders, "accept-encoding", json_object_new_string(""));

    // headers: user-agent
    json_object_object_add(jsonGatewayRequestHeaders, "user-agent", json_object_new_string(""));

    // headers
    json_object_object_add(jsonGatewayRequest, "headers", jsonGatewayRequestHeaders);

    // cookies
    
    // parameters

    // attributes
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
    return r->method;
}
const char* getUrl(SSORestRequestObject* r)
{
    return r->uri;
}
const char* getProtocol(SSORestRequestObject* r)
{
    return r->protocol;
}
const char* getCharacterEncoding(SSORestRequestObject* r)
{
    return r->content_encoding;
}
int getContentLength(SSORestRequestObject* r)
{
    return r->clength;
}
const char* getContentType(SSORestRequestObject* r)
{
    return r->content_type;
}
const char* getContextPath(SSORestRequestObject* r)
{
    return ap_document_root(r);
}
const char* getLocalAddr(SSORestRequestObject* r)
{
    return r->connection->local_ip;
}
const char* getLocalName(SSORestRequestObject* r)
{
    return r->server->server_hostname;
}
int getLocalPort(SSORestRequestObject* r)
{
    return 80;
}
const char* getRemoteAddr(SSORestRequestObject* r)
{
    return r->useragent_ip;
}
const char* getRemoteHost(SSORestRequestObject* r)
{
    return r->useragent_ip;
}
int getRemotePort(SSORestRequestObject* r)
{
    return r->useragent_addr->port;
}
// const char* getSecure(SSORestRequestObject* r)
// {
    
// }
// const char* getScheme(SSORestRequestObject* r)
// {
    
// }
// const char* getServerName(SSORestRequestObject* r)
// {
    
// }
// const char* getServerPort(SSORestRequestObject* r)
// {
    
// }
// const char* getServletPath(SSORestRequestObject* r)
// {
    
// }
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