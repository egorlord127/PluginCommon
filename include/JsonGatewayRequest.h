#include <json-c/json.h>

typedef struct JSonGatewayRequest JSonGatewayRequest;
struct JSonGatewayRequest{
    json_object *json;
    void (*setAttributes)(JSonGatewayRequest*, const char*, const char*);
    void (*buildJsonRequest)(JSonGatewayRequest*);
};

void buildJsonRequest(JSonGatewayRequest* self);
void setAttributes(JSonGatewayRequest* self, const char* key, const char* value);