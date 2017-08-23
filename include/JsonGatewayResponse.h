#include <json-c/json.h>
typedef struct JSonGatewayResponse JSonGatewayResponse;
struct JSonGatewayResponse{
    json_object *json;
    json_object *jsonRequest;
    json_object *jsonResponse;
    json_object *jsonResponseHeader;
    json_object *jsonResponseCookies;
    void (*parseJson)(const char*, JSonGatewayResponse*);
};

void parseJson(const char*, JSonGatewayResponse*);
