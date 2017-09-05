#include "Global.h"
#include <curl/curl.h>

#define BUF_BLOCK_SIZE (4*1024)
#define BUF_BLOCK_UPPER_LIMIT (8ul*1024*1024*1024)

typedef struct {
    SSORestPluginPool* pool;
    char*       response_data;
    size_t      response_size;
    size_t      response_capacity;
} CurlContextRec;

size_t CurlRecvData(void *buffer, size_t size, size_t nmemb, void *userdata);
int CurlTraceDebug(CURL *handle, curl_infotype type, char *data, size_t size, void *userp);
