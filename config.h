#include "apr_hash.h"

#include <jansson.h>

struct config
{
    char *opa_url;
    json_t *opa_decision_grant;
    int auth_needed;

    char *ip_key_name;
    char *method_key_name;
    char *version_key_name;
    char *url_key_name;
    char *auth_key_name;

    apr_hash_t *headers;
    apr_hash_t *query_string;
    apr_hash_t *form_fields;
    json_t *custom;
    
    char *header_array_name;
    char *query_string_array_name;
    char *form_field_array_name;

    int send_all_headers;
    int send_all_queries;
    int send_all_form_fields;
    int max_form_size;
};

void *create_dir_configuration(apr_pool_t *p, char *dir);
void *merge_dir_configuration(apr_pool_t *p, void *base, void *add);
