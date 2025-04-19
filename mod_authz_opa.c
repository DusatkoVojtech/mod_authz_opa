#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "mod_auth.h"
#include "util_script.h"
#include "http_log.h"

#include <curl/curl.h>
#include <jansson.h>

#include "config.h"

#define RESPONSE_SIZE 256

extern const command_rec directives[];
static void register_hooks(apr_pool_t *p);

AP_DECLARE_MODULE(authz_opa) =
{
    STANDARD20_MODULE_STUFF,
    create_dir_configuration,
    merge_dir_configuration,
    NULL,
    NULL,
    directives,
    register_hooks
};

struct http_response
{
    apr_pool_t *req_pool;
    char *bytes;
    int count;
    int allocated;
};

size_t save_response_part(void *response_part, size_t size, size_t nmemb, void *save_buffer)
{
    struct http_response *response = save_buffer;
    if (response->count + nmemb > response->allocated) {
        response->allocated *= 2;
        char *new_buffer = apr_palloc(response->req_pool, response->allocated);
        //check
        memcpy(new_buffer, response->bytes, response->count);
        response->bytes = new_buffer;
    }
    memcpy(response->bytes + response->count, response_part, nmemb);
    response->count += nmemb;

    return nmemb;
}

char *perform_opa_request(request_rec *r, const struct config *c, char *json)
{
    CURL *curl = curl_easy_init();

    struct http_response response = { r->pool, NULL, 0, 0 };
    response.bytes = apr_palloc(r->pool, RESPONSE_SIZE);
    response.allocated = RESPONSE_SIZE;

    curl_easy_setopt(curl, CURLOPT_URL, c->opa_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, save_response_part);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode code = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    response.bytes[response.count] = '\0';

    return response.bytes;
}

json_t *encode_claims(const apr_array_header_t *extracted_claims, apr_hash_t *configured_claims,
              int send_all, char *array_name)
{
    json_t *object = json_object();
    json_t *array = NULL;
    if (array_name != NULL) {
        array = json_array();
    }

    apr_table_entry_t *h = (apr_table_entry_t *) extracted_claims->elts;
    for (int i = 0; i < extracted_claims->nelts; i++) {
        char *key = apr_hash_get(configured_claims, h[i].key, strlen(h[i].key));
        if (send_all) {
            key = h[i].key;
        }
        if (key != NULL) {
            json_t *val = (h[i].val != NULL && *(h[i].val) != '\0') ? json_string(h[i].val) : json_null();
            if (array_name == NULL) {
                json_object_set_new(object, key, val);

            } else {
                json_t *claim = json_object();
                json_object_set_new(claim, key, val);
                json_array_append_new(array, claim);
            }
        }
    }

    if (array != NULL) {
        json_object_set_new(object, array_name, array);
    }
    return object;
}

json_t *encode_headers(request_rec *r, const struct config *cfg)
{
    const apr_array_header_t *headers = apr_table_elts(r->headers_in);
    return encode_claims(headers, cfg->headers, cfg->send_all_headers, cfg->header_array_name);
}

json_t *encode_query_string(request_rec *r, const struct config *cfg)
{
    apr_table_t *query_string;
    ap_args_to_table(r, &query_string);
    const apr_array_header_t *query_args = apr_table_elts(query_string);
    return encode_claims(query_args, cfg->query_string, cfg->send_all_queries, cfg->query_string_array_name);
}

json_t *encode_form_fields(request_rec *r, const struct config *cfg)
{
    apr_array_header_t *form_data;
    if (ap_parse_form_data(r, NULL, &form_data, -1, cfg->max_form_size) != OK || form_data == NULL) {
        return json_object();
    }
    ap_form_pair_t *form_pairs = (ap_form_pair_t *) form_data->elts;

    apr_table_t *new_table = apr_table_make(r->pool, form_data->nelts);
    apr_size_t value_len;
    apr_off_t brigade_len;
    char *value;
    for (int i = 0; i < form_data->nelts; i++) {
        apr_brigade_length(form_pairs[i].value, 1, &brigade_len);
        value_len = brigade_len;
        value = apr_palloc(r->pool, value_len + 1);
        apr_brigade_flatten(form_pairs[i].value, value, &value_len);
        apr_table_setn(new_table, form_pairs[i].name, value);
    }

    return encode_claims(apr_table_elts(new_table), cfg->form_fields,
                 cfg->send_all_form_fields, cfg->form_field_array_name);
}

char *build_json(request_rec *r, const struct config *c)
{
    json_t *request_info = json_object();
    if (c->ip_key_name) {
        json_object_set_new(request_info, c->ip_key_name, json_string(r->useragent_ip));
    }
    if (c->method_key_name) {
        json_object_set_new(request_info, c->method_key_name, json_string(r->method));
    }
    if (c->url_key_name) {
        json_object_set_new(request_info, c->url_key_name, json_string(r->uri));
    }
    if (c->version_key_name) {
        json_object_set_new(request_info, c->version_key_name, json_string(r->protocol));
    }
    if (c->auth_key_name) {
        json_object_set_new(request_info, c->auth_key_name, json_string(r->user));
    }

    json_t *objects[] = { encode_headers(r, c), encode_query_string(r, c),
                 encode_form_fields(r, c), json_deep_copy(c->custom) }; 

    for (size_t i = 0; i < 4; i++) {
        json_object_update_new(request_info, objects[i]);
    }

    json_t *to_send = json_object();
    json_object_set_new(to_send, "input", request_info);
    char *json = json_dumps(to_send, JSON_COMPACT);

    return json;
}

static authz_status opa_check_authorization(request_rec *r, const char *require_line, const void *parsed_require_line)
{
    const struct config *c = ap_get_module_config(r->per_dir_config, &authz_opa_module);
    if (c->opa_url == NULL || c->opa_decision_grant == NULL) {
        return AUTHZ_DENIED;
    }
    
    if (c->auth_needed && r->user == NULL) {
        return AUTHZ_DENIED_NO_USER;
    }

    char *json = build_json(r, c);
    char *decision = perform_opa_request(r, c, json);
    json_error_t error;
    json_t *result = json_loads(decision, 0, &error);
    if (result == NULL) {
        return AUTHZ_DENIED;
    }

    if (json_equal(result, c->opa_decision_grant)) {
        return AUTHZ_GRANTED;
    }
    return AUTHZ_DENIED;
}

static const authz_provider authz_opa_provider =
{
    &opa_check_authorization,
    NULL
};

static void register_hooks(apr_pool_t *p)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "opa",
                  AUTHZ_PROVIDER_VERSION, &authz_opa_provider,
                  AP_AUTH_INTERNAL_PER_CONF);
}
