#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "mod_auth.h"
#include "util_script.h"
#include "http_log.h"

#include <curl/curl.h>
#include <jansson.h>

#include "config.h"

#define RESPONSE_START_ALLOC_SIZE 1024

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

/* This function will be called after the thread exits. */
static apr_status_t cleanup_curl_handle(void *handle)
{
    curl_easy_cleanup(handle);
    return APR_SUCCESS;
}

/* Loading the response body passed from libcurl into memory */
static size_t save_response_part(void *response_part, size_t size, size_t nmemb, void *save_buffer)
{
    struct http_response *response = save_buffer;
    if (response->count + nmemb >= response->allocated) {
        response->allocated *= 2;
        char *new_buffer = apr_palloc(response->req_pool, response->allocated);
        memcpy(new_buffer, response->bytes, response->count);
        response->bytes = new_buffer;
    }
    memcpy(response->bytes + response->count, response_part, nmemb);
    response->count += nmemb;

    return nmemb;
}

static char *perform_opa_request(request_rec *r, const struct config *c, char *json)
{
    CURL *curl_handle;
    /* The curl handle is initialized once per thread and preserved until the thread exits
     * in order to allow for persistent connections. */
    apr_status_t status = apr_thread_data_get(&curl_handle, "curl_handle", ap_thread_current());
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "apr_thread_data_get failed");
    }

    if (curl_handle == NULL) {
        curl_handle = curl_easy_init();
        if (curl_handle == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "curl_easy_init failed");
            return NULL;
        }

        curl_easy_setopt(curl_handle, CURLOPT_URL, c->opa_url);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, save_response_part);

        status = apr_thread_data_set(curl_handle, "curl_handle", cleanup_curl_handle, ap_thread_current()); 
        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "apr_thread_data_set failed");
        }
    }

    struct http_response response = { r->pool, NULL, 0, 0 };
    response.allocated = RESPONSE_START_ALLOC_SIZE;
    response.bytes = apr_palloc(r->pool, response.allocated);

    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);
    
    CURLcode curl_code = curl_easy_perform(curl_handle);
    if (curl_code != CURLE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "curl_easy_perform: %s", curl_easy_strerror(curl_code));
        return NULL;
    }

    /* Ensuring that the response JSON is a valid string */
    response.bytes[response.count] = '\0';

    return response.bytes;
}

static json_t *encode_claims(const apr_array_header_t *extracted_claims, apr_hash_t *configured_claims,
              int send_all, char *array_name)
{
    json_t *object = json_object();
    json_t *array = NULL;
    /* Optionally placing the data into an JSON array */
    if (array_name != NULL) {
        array = json_array();
    }

    apr_table_entry_t *h = (apr_table_entry_t *) extracted_claims->elts;
    for (int i = 0; i < extracted_claims->nelts; i++) {
        char *key = apr_hash_get(configured_claims, h[i].key, strlen(h[i].key));
        // Using the default name for key in case of sending everything
        if (key == NULL && send_all) {
            key = h[i].key;
        }
        if (key != NULL) {
            // empty string counts as a null value
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

/* Extracting the HTTP request data */
static json_t *encode_headers(request_rec *r, const struct config *cfg)
{
    const apr_array_header_t *headers = apr_table_elts(r->headers_in);
    return encode_claims(headers, cfg->headers, cfg->send_all_headers, cfg->header_array_name);
}

static json_t *encode_query_string(request_rec *r, const struct config *cfg)
{
    apr_table_t *query_string;
    ap_args_to_table(r, &query_string);
    const apr_array_header_t *query_args = apr_table_elts(query_string);
    return encode_claims(query_args, cfg->query_string, cfg->send_all_queries, cfg->query_string_array_name);
}

static json_t *encode_form_fields(request_rec *r, const struct config *cfg)
{
    apr_array_header_t *form_data;
    if (ap_parse_form_data(r, NULL, &form_data, -1, cfg->max_form_size) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Couldn't parse form data");
        return json_object();
    }
    if (form_data == NULL) {
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
        value[brigade_len] != '\0';
        apr_table_setn(new_table, form_pairs[i].name, value);
    }

    return encode_claims(apr_table_elts(new_table), cfg->form_fields,
                 cfg->send_all_form_fields, cfg->form_field_array_name);
}

static char *build_json(request_rec *r, const struct config *c)
{
    json_t *request_info = json_object();
    // retrieving basic request information
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

    // encoding category data
    json_t *objects[] = { encode_headers(r, c), encode_query_string(r, c),
                 encode_form_fields(r, c), json_deep_copy(c->custom) }; 

    for (size_t i = 0; i < 4; i++) {
        json_object_update_new(request_info, objects[i]);
    }

    json_t *to_send = json_object();
    /* The JSON object sent to opa needs to be enclosed inside an "input" key. */
    json_object_set_new(to_send, "input", request_info);
    char *json = json_dumps(to_send, JSON_COMPACT);
    json_decref(to_send);

    return json;
}

static authz_status check_opa_decision(request_rec *r, char *decision_string, char **grant_path)
{
    json_t *decision_json = json_loads(decision_string, 0, NULL);
    if (decision_json == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to decode OPA response as JSON");
        return AUTHZ_DENIED;
    }

    json_t *value = decision_json;
    for (int i = 0; grant_path[i] != NULL; i++) {
        value = json_object_get(value, grant_path[i]);
        if (value == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "JSON key %s does not exist in the response", grant_path[i]);
            json_decref(decision_json);
            return AUTHZ_DENIED;
        }
    }

    if (json_is_true(value)) {
        json_decref(decision_json);
        return AUTHZ_GRANTED;
    }

    json_decref(decision_json);
    return AUTHZ_DENIED;
}

static authz_status opa_check_authorization(request_rec *r, const char *require_line, const void *parsed_require_line)
{
    const struct config *c = ap_get_module_config(r->per_dir_config, &authz_opa_module);

    if (c->auth_needed && r->user == NULL) {
        // asking for authentication if needed
        return AUTHZ_DENIED_NO_USER;
    }

    char *json = build_json(r, c);
    if (json == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to encode request into JSON");
        return AUTHZ_DENIED;
    }

    char *decision = perform_opa_request(r, c, json);
    free(json);
    if (decision == NULL) {
        return AUTHZ_DENIED;
    }

    return check_opa_decision(r, decision, c->opa_decision_grant);
}

static const authz_provider authz_opa_provider =
{
    &opa_check_authorization,
    NULL
};

static apr_status_t curl_cleanup_library(void *arg)
{
    curl_global_cleanup();
    return APR_SUCCESS;
}

/* libcurl initialization */
static int init_module(apr_pool_t *conf, apr_pool_t *log, apr_pool_t *temp, server_rec *s)
{
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, log, "Failed to initialize libcurl");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_pool_cleanup_register(conf, NULL, curl_cleanup_library, apr_pool_cleanup_null);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(init_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "opa",
                  AUTHZ_PROVIDER_VERSION, &authz_opa_provider,
                  AP_AUTH_INTERNAL_PER_CONF);
}
