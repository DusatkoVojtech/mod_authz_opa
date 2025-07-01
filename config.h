#include "apr_hash.h"

#include <jansson.h>

static const char *const SSL_VARS[] = {
    "HTTPS",
    "SSL_TLS_SNI",
    "SSL_VERSION_INTERFACE",
    "SSL_VERSION_LIBRARY",
    "SSL_PROTOCOL",
    "SSL_SECURE_RENEG",
    "SSL_COMPRESS_METHOD",
    "SSL_CIPHER",
    "SSL_CIPHER_EXPORT",
    "SSL_CIPHER_USEKEYSIZE",
    "SSL_CIPHER_ALGKEYSIZE",
    "SSL_CLIENT_VERIFY",
    "SSL_CLIENT_M_VERSION",
    "SSL_CLIENT_M_SERIAL",
    "SSL_CLIENT_V_START",
    "SSL_CLIENT_V_END",
    "SSL_CLIENT_V_REMAIN",
    "SSL_CLIENT_S_DN",
    "SSL_CLIENT_I_DN",
    "SSL_CLIENT_A_KEY",
    "SSL_CLIENT_A_SIG",
    "SSL_CLIENT_CERT",
    "SSL_CLIENT_CERT_RFC4523_CEA",
    "SSL_SERVER_M_VERSION",
    "SSL_SERVER_M_SERIAL",
    "SSL_SERVER_V_START",
    "SSL_SERVER_V_END",
    "SSL_SERVER_S_DN",
    "SSL_SERVER_I_DN",
    "SSL_SERVER_A_KEY",
    "SSL_SERVER_A_SIG",
    "SSL_SERVER_CERT",
    "SSL_SESSION_ID",
    "SSL_SESSION_RESUMED",
    "SSL_SRP_USER",
    "SSL_SRP_USERINFO",
    NULL
};

struct config
{
    char *opa_url;
    char **opa_decision_grant;
    int auth_needed;

    char *ip_key_name;
    char *method_key_name;
    char *version_key_name;
    char *url_key_name;
    char *filepath_key_name;
    char *auth_key_name;
    char *query_string;

    apr_hash_t *headers;
    apr_hash_t *query_parameters;
    apr_hash_t *form_fields;
    apr_hash_t *env_vars;
    apr_table_t *env_prefixes;
    json_t *custom;
    
    char *headers_array_name;
    char *query_string_array_name;
    char *form_data_array_name;
    char *vars_array_name;

    int send_all_headers;
    int parse_query_string;
    int send_all_form_fields;
    int send_all_vars;
    int max_form_size;
};

void *create_dir_configuration(apr_pool_t *p, char *dir);
void *merge_dir_configuration(apr_pool_t *p, void *base, void *add);
