#include "JsonGatewayRequest.h"
JSonGatewayRequest* buildJsonGatewayRequest(SSORestRequestObject* request)
{
    JSonGatewayRequest *jsonGatewayRequest = json_object_new_object();

    // method
    json_object_object_add(jsonGatewayRequest, "method", json_object_new_string(""));
    
    // url
    json_object_object_add(jsonGatewayRequest, "url", json_object_new_string(""));
    
    // protocol
    json_object_object_add(jsonGatewayRequest, "protocol", json_object_new_string(""));

    // characterEncoding
    json_object_object_add(jsonGatewayRequest, "characterEncoding", json_object_new_string(""));

    // contentLength
    json_object_object_add(jsonGatewayRequest, "contentLength", json_object_new_int(0));

    // contentType
    json_object_object_add(jsonGatewayRequest, "contentType", json_object_new_string(""));

    // contextPath
    json_object_object_add(jsonGatewayRequest, "contextPath", json_object_new_string(""));

    // localAddr
    json_object_object_add(jsonGatewayRequest, "localAddr", json_object_new_string(""));

    // localName
    json_object_object_add(jsonGatewayRequest, "localName", json_object_new_string(""));

    // localPort
    json_object_object_add(jsonGatewayRequest, "localPort", json_object_new_int(0));

    // remoteAddr
    json_object_object_add(jsonGatewayRequest, "remoteAddr", json_object_new_string(""));

    // remoteHost
    json_object_object_add(jsonGatewayRequest, "remoteHost", json_object_new_string(""));

    // remotePort
    json_object_object_add(jsonGatewayRequest, "remotePort", json_object_new_int(0));

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