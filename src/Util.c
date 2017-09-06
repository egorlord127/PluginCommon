#include "Util.h"
#include <string.h>
#include <openssl/hmac.h>

#ifndef MAX_SAVED_LENGTHS
#define MAX_SAVED_LENGTHS (32)
#endif

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static inline int is_base64(unsigned char c) {
    return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c == '+') || (c == '/'));
}

int base64_encode(const unsigned char* in, unsigned char* out, unsigned int in_len)
{
    int length = 0;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(in++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
            {
                length++;
                *out++ = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
        {
            length++;
            *out++ = base64_chars[char_array_4[j]];
        }
        while((i++ < 3))
        {
            length++;
            *out++ = '=';
        }
    }

    return length;
}

int base64_decode(const unsigned char *in, unsigned char *out, unsigned int in_len) {
    int i = 0;
    int j = 0;
    int in_ = 0;
    int length = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && ( in[in_] != '=') && is_base64(in[in_])) {
        char_array_4[i++] = in[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
            {
                char *result = strchr(base64_chars, char_array_4[i]);
                int position = result - base64_chars;
                char_array_4[i] = position;
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
            {
                *out++ = char_array_3[i];
                length++;
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
        {
            char *result = strchr(base64_chars, char_array_4[j]);
            int position = result - base64_chars;
            char_array_4[j] = position;
        }
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) 
        {
            *out++ = char_array_3[j];
            length++;
        }
    }
    return length;
}

char * ssorest_pstrcat(SSORestPluginPool *a, ...)
{
	char *cp, *argp, *res;
	size_t saved_lengths[MAX_SAVED_LENGTHS];
	int nargs = 0;

	/* Pass one --- find length of required string */

	size_t len = 0;
	va_list adummy;

	va_start(adummy, a);

	while ( (cp = va_arg(adummy, char *)) != NULL ) {
		size_t cplen = strlen(cp);
		if ( nargs < MAX_SAVED_LENGTHS ) {
			saved_lengths[nargs++] = cplen;
		}
		len += cplen;
	}

	va_end(adummy);

	/* Allocate the required string */

	res = (char *) ssorest_pcalloc(a, len + 1);
	cp = res;

	/* Pass two --- copy the argument strings into the result space */

	va_start(adummy, a);

	nargs = 0;
	while ( (argp = va_arg(adummy, char *)) != NULL ) {
		if ( nargs < MAX_SAVED_LENGTHS ) {
			len = saved_lengths[nargs++];
		} else {
			len = strlen(argp);
		}
		memcpy(cp, argp, len);
		cp += len;
	}

	va_end(adummy);

	*cp = '\0';
	return res;
}

char *toStringSafety(SSORestPluginPool *pool, unsigned char *str, int len)
{
    if (str == NULL) {
        return "";
    }
    char *dst = ssorest_pcalloc(pool, len + 1);
    strncpy(dst, (const char *) (str), len);
    dst[len] = '\0';
    return dst;
}

inline int ishex(int x)
{
    return (x >= '0' && x <= '9') ||
            (x >= 'a' && x <= 'f') ||
            (x >= 'A' && x <= 'F');
}

int unescape_str(char *s, char *dec)
{
    char *o;
    const char *end = s + strlen(s);
    int c;

    for (o = dec; s <= end; o++) {
        c = *s++;
        if (c == '+')
            c = ' ';
        else if (c == '%' && (!ishex(*s++) ||
                !ishex(*s++) ||
                !sscanf(s - 2, "%2x", &c)))
            return -1;

        if (dec)
            *o = c;
    }

    return o - dec;
}

void generateSecureRandomString(char *s, const int length)
{
    const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int i;
    for (i = 0; i < length; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[length] = '\0';
}

const char *computeRFC2104HMAC(SSORestRequestObject *r, char *data, const char *key)
{
    unsigned char *mdString;
    unsigned char *src;
    unsigned char *result;
    unsigned char  result_len;
    if (key == NULL || data == NULL)
    {
        logError(r, "Could not parse parameter");   
        return NULL;
    }

    /* Generate HMAC using openssl */
    mdString = HMAC(EVP_sha1(), key, strlen(key), (u_char*) data, strlen(data), NULL, NULL);

    /* Allocate Memory for generating hmac */
    src = (unsigned char *) ssorest_pcalloc(r->pool, SHA1_DIGESTLENGTH + 1);
    if(src == NULL)
    {
        logError(r, "Could not Allocate Memory");
        return NULL;
    }
    memcpy(src, mdString, SHA1_DIGESTLENGTH);
    src[SHA1_DIGESTLENGTH] = '\0';

    /* Base64Encode using Nginx Utility Api */
    result_len = (((SHA1_DIGESTLENGTH + 2) / 3) * 4);
    result = (unsigned char *) ssorest_pcalloc(r->pool, result_len + 1);

    if(result == NULL)
    {
        logError(r, "Could not Allocate Memory");
        return NULL;   
    }
    result_len = base64_encode(src, result, SHA1_DIGESTLENGTH);
    result[result_len] = '\0';

    return (const char*) result;
}
