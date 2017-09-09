#include "CurlWrapper.h"
#include "Logging.h"
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

int CurlTraceDebug(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
    SSORestRequestObject *r = (SSORestRequestObject *)userp;
    const char *text;
    (void)handle; /* prevent compiler warning */
    char buf[200];
    char *p = buf;
    char *pos;
    switch(type) {  
    case CURLINFO_TEXT:

        if ((pos=strchr(data, '\n')) != NULL)
            *pos = '\0';
        sprintf(buf,  "== Info: %s", data);
        logError(r, buf);
        return 0;
    default:
        return 0;
    case CURLINFO_HEADER_OUT:
        text = "=> Send header";
        break;
    case CURLINFO_DATA_OUT:
        text = "=> Send data";
        break;
    case CURLINFO_SSL_DATA_OUT:
        text = "=> Send SSL data";
        break;
    case CURLINFO_HEADER_IN:
        text = "<= Recv header";
        break;
    case CURLINFO_DATA_IN:
        text = "<= Recv data";
        break;
    case CURLINFO_SSL_DATA_IN:
        text = "<= Recv SSL data";
        break;
    }

    // Logging
    size_t i;
    size_t c;

    unsigned int width=0x10;
    unsigned char *ptr = (unsigned char *) data;
    sprintf(buf, "%s, %10.10ld bytes (0x%8.8lx)", text, (long)size, (long)size);
    logError(r, "%s", buf);

    for(i=0; i<size; i+= width) {
        p = buf;
        sprintf(p, "0x%4.4lx: ", (long)i);
        p+=8;

		for(c = 0; c < width; c++)
		{
			if(i+c < size)
			{
				sprintf(p, "%02x ", ptr[i+c]);
				p+=3;
			}
			else
			{
				sprintf(p, "   ");
				p+=3;   
			}
		}

        for(c = 0; (c < width) && (i+c < size); c++) {
            sprintf(p, "%c",
              (ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
            p++;
        }
        *p = '\0';
        logError(r, "%s", buf);
    }
    return 0;
}