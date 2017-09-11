/**
 * @file   Util.h
 * @author Egor Lord <elord@idfconnect.com>
 *
 */

#include "Global.h"
#define SHA1_DIGESTLENGTH 20

int     base64_encode(const unsigned char* in, unsigned char* out, unsigned int in_len);
int     base64_decode(const unsigned char *in, unsigned char *out, unsigned int in_len);
char   *ssorest_pstrcat(SSORestPluginPool *a, ...);
char   *toStringSafety(SSORestPluginPool *pool, unsigned char *str, int len);
int     unescape_str(char *s, char *dec);
char *escape_str(SSORestPluginPool *p, const char *src);
void    generateSecureRandomString(char *s, const int length);
const char *computeRFC2104HMAC(SSORestRequestObject *r, char *data, const char *key);