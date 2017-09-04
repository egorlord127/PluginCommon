#include <ngx_http.h>
int     base64_encode(const unsigned char* in, unsigned char* out, unsigned int in_len);
int     base64_decode(const unsigned char *in, unsigned char *out, unsigned int in_len);
void    generateSecureRandomString(char *s, const int length);
char   *ssorest_pstrcat(ngx_pool_t *a, ...);
char   *toStringSafety(ngx_pool_t *pool, ngx_http_variable_value_t *v);
char   *makeNullTerminated(ngx_pool_t *pool, u_char *str, int len);