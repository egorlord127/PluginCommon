#include "CurlWrapper.h"
#include <curl/curl.h>
#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

size_t CurlRecvData(void *buffer, size_t size, size_t nmemb, void *userdata)
{
	const size_t chunk_size = size * nmemb;
	CurlContextRec *context = (CurlContextRec*)userdata;
	size_t new_size  = context->response_size + chunk_size + 1;
	new_size         = new_size + BUF_BLOCK_SIZE - new_size % BUF_BLOCK_SIZE;
	char *new_data;
	size_t new_capacity;

	if ( context->response_data == NULL ) {
		context->response_data = ssorest_palloc(context->pool, new_size);
		context->response_size = chunk_size;
		context->response_capacity = new_size;
		memcpy(context->response_data, buffer, chunk_size);
		context->response_data[chunk_size] = '\0';
	} else {
		if ( new_size > context->response_capacity ) {
			if ( context->response_capacity < BUF_BLOCK_UPPER_LIMIT ) {
				new_capacity = max(new_size, context->response_capacity*2);
			} else {
				new_capacity = new_size;
			}
			new_data = ssorest_palloc(context->pool, new_capacity);
			memcpy(new_data, context->response_data, context->response_size);
			context->response_data = new_data;
			context->response_capacity = new_capacity;
		}
		memcpy(context->response_data + context->response_size, buffer, chunk_size);
		context->response_data[context->response_size + chunk_size] = '\0';
		context->response_size += chunk_size;
	}
	return chunk_size;
}