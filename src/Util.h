#include "Global.h"
#define SHA1_DIGESTLENGTH 20

int     base64_encode(const unsigned char* in, unsigned char* out, unsigned int in_len);
int     base64_decode(const unsigned char *in, unsigned char *out, unsigned int in_len);
char   *ssorest_pstrcat(SSORestPluginPool *a, ...);
char   *toStringSafety(SSORestPluginPool *pool, unsigned char *str, int len);
int     unescape_str(char *s, char *dec);
void    generateSecureRandomString(char *s, const int length);