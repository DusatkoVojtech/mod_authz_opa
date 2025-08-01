#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "mod_auth.h"
#include "util_script.h"
#include "http_log.h"
#include "http_ssl.h"
#include "apr_strings.h"
#include "apr_lib.h"

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

/* This function will be called after a thread exits. */
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
    CURL *curl_handle = NULL;
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

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OPA request sent to %s", c->opa_url);

    return response.bytes;
}

static json_t *encode_claims(const apr_array_header_t *extracted_claims, apr_hash_t *configured_claims,
              int send_all, char *array_name)
{
    json_t *fields = json_object();
    if (fields == NULL) {
        return NULL;
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

            json_t *prev_val = json_object_get(fields, key);
            if (prev_val == NULL) {
                json_object_set_new(fields, key, val);
            } else if (json_is_array(prev_val)) {
                json_array_append_new(prev_val, val);
            } else {
                json_t *value_array = json_array();
                prev_val = json_copy(prev_val);
                json_array_append_new(value_array, prev_val);
                json_array_append_new(value_array, val);
                json_object_set_new(fields, key, value_array);
            }
        }
    }

    if (json_object_size(fields) == 0) {
        json_decref(fields);
        return NULL;
    }
    json_t *object = json_object();
    if (object == NULL) {
        json_decref(fields);
        return NULL;
    }
    json_object_set_new(object, array_name, fields);
    return object;
}

/* Extracting the HTTP request data */
static json_t *encode_json_variables(request_rec *r, apr_array_header_t *already_json, apr_table_t *received)
{
    json_t *result = json_object();
    if (result == NULL) {
        return NULL;
    }

    char **var = (char **) already_json->elts;
    for (int i = 0; i < already_json->nelts; i++) {
        const char *val = apr_table_get(received, var[i]);
        if (val != NULL) {
            json_error_t error;
            json_t *json_val = json_loads(val, 0, &error);
            apr_table_unset(received, var[i]);
            if (json_val == NULL) {
                char *error_text = apr_pstrdup(r->pool, error.text);
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                        "Error while decoding \"%s\": %s; variable was not sent", var[i], error_text);
                continue;
            }
            if (json_object_set_new(result, var[i], json_val) == -1) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to add var %s to JSON", var[i]);
            }
        }
    }

    if (json_object_size(result) == 0) {
        json_decref(result);
        return NULL;
    }

    return result;
}

static json_t *encode_headers(request_rec *r, const struct config *cfg)
{
    apr_table_t *headers = apr_table_copy(r->pool, r->headers_in);
    json_t *json_headers = encode_json_variables(r, cfg->json_headers, headers);

    json_t *result = encode_claims(apr_table_elts(headers), cfg->headers,
                                   cfg->send_all_headers, cfg->headers_array_name);

    if (json_headers != NULL) {
        if (result == NULL) {
            result = json_object();
            json_object_set_new(result, cfg->headers_array_name, json_object());
        }
        json_t *encoded_headers = json_object_get(result, cfg->headers_array_name);
        json_object_update_new(encoded_headers, json_headers);
    }

    if (result != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "Finished encoding the headers into JSON");
    }
    return result;
}

static int hex_to_num(char digit)
{
    if (digit >= 'A') {
        return 10 + ((digit & 0xdf) - 'A');
    }
    return digit - '0';
}

static char *percent_encoding(apr_pool_t *p, char *value)
{
    char *val = apr_pstrdup(p, value);
    int j = 0;
    for (int i = 0; value[i] != '\0'; i++, j++) {
        if (value[i] == '%') {
            if (value[i + 1] == '\0' || value[i + 2] == '\0' ||
                    !apr_isxdigit(value[i + 1]) || !apr_isxdigit(value[i + 2])) {
                return NULL;
            }
            val[j] = 16 * hex_to_num(value[i + 1]);
            val[j] += hex_to_num(value[i + 2]);
            if (val[j] == '\0') {
                return NULL;
            }

            i += 2;
        } else {
            val[j] = val[i];
        }
    }
    val[j] = '\0';
    return val;
}

static json_t *encode_query_string(request_rec *r, const struct config *cfg)
{
    if (!cfg->parse_query_string || r->args == NULL) {
        return NULL;
    }
    char *query_string = apr_pstrdup(r->pool, r->args);
    char *next;
    apr_table_t *query_args = apr_table_make(r->pool, APR_DATA_STRUCT_SIZE);

    for (char *param = apr_strtok(query_string, "&", &next); param != NULL; param = apr_strtok(NULL, "&", &next)) {
        char *value = param;
        for (int i = 0; param[i] != '\0'; i++) {
            if (apr_isspace(param[i]) || !apr_isascii(param[i])) {
                return NULL;
            }
            if (param[i] == '=') {
                if (value != param) {
                    return NULL;
                }
                param[i] = '\0';
                value = param + i + 1;
                if (*value == '\0') {
                    value = NULL;
                }
            }
        }
        if (value == param) {
            return NULL;
        }

        param = percent_encoding(r->pool, param);
        value = percent_encoding(r->pool, value);
        apr_table_add(query_args, param, value);
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "Finished parsing the query string");

    return encode_claims(apr_table_elts(query_args), cfg->query_parameters,
            apr_hash_count(cfg->query_parameters) == 0, cfg->query_string_array_name);
}

static json_t *encode_form_fields(request_rec *r, const struct config *cfg)
{
    apr_array_header_t *form_data;
    if (ap_parse_form_data(r, NULL, &form_data, -1, cfg->max_form_size) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Couldn't parse form data");
        return NULL;
    }
    if (form_data == NULL) {
        return NULL;
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

    json_t *result = encode_claims(apr_table_elts(new_table), cfg->form_fields,
                 cfg->send_all_form_fields, cfg->form_data_array_name);
    if (result != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "Finished setting up form data fields");
    }

    return result;
}

static void add_ssl_variables(request_rec *r, const struct config *cfg, apr_table_t *vars_table)
{
    if (cfg->send_all_vars || cfg->env_prefixes->nelts > 0 || cfg->env_regex->nelts > 0) {
        for (int i = 0; SSL_VARS[i] != NULL; i++) {
            const char *value = ap_ssl_var_lookup(r->pool, r->server, r->connection, r, SSL_VARS[i]);
            if (value != NULL && *value != '\0') {
                apr_table_set(vars_table, SSL_VARS[i], value);
            }
        }
    } else {
        for (apr_hash_index_t *i = apr_hash_first(r->pool, cfg->env_vars); i != NULL; i = apr_hash_next(i)) {
            const void *var;
            apr_hash_this(i, &var, NULL, NULL);
            const char *value = ap_ssl_var_lookup(r->pool, r->server, r->connection, r, var);
            if (value != NULL && *value != '\0') {
                apr_table_set(vars_table, var, value);
            }
        }
    }
}

static json_t *match_regex_vars(request_rec *r, apr_array_header_t *expressions, const apr_array_header_t *variables)
{
    json_t *result = json_object();
    if (result == NULL) {
        return NULL;
    }

    ap_regex_t **regexes = (ap_regex_t **) expressions->elts;
    apr_table_entry_t *vars = (apr_table_entry_t *) variables->elts;

    for (int i = 0; i < expressions->nelts; i++) {
        for (int j = 0; j < variables->nelts; j++)
        if (ap_regexec(regexes[i], vars[j].key, 0, NULL, 0) != AP_REG_NOMATCH) {
            json_object_set_new(result, vars[j].key, json_string(vars[j].val));
        }
    }

    if (json_object_size(result) == 0) {
        json_decref(result);
        return NULL;
    }
    return result;
}

static json_t *encode_env_variables(request_rec *r, const struct config *cfg)
{
    /* putting additional variables into the table */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    apr_table_t *vars_table = apr_table_copy(r->pool, r->subprocess_env);
    add_ssl_variables(r, cfg, vars_table);

    /* starting with variables which are supposed to have JSON values */
    json_t *json_variables = encode_json_variables(r, cfg->json_env, vars_table);

    /* matching variables to potential prefixes or regular expressions */
    json_t *prefix_variables = json_object();

    const apr_array_header_t *variables = apr_table_elts(vars_table);
    char **prefixes = (char **) cfg->env_prefixes->elts;
    const apr_table_entry_t *var = (apr_table_entry_t *) variables->elts;

    for (int i = 0; i < cfg->env_prefixes->nelts; i++) {
        for (int j = 0; j < variables->nelts; j++) {
            int prefix_length = strlen(prefixes[i]);
            if (prefix_length <= strlen(var[j].key) &&
                    strncmp(var[j].key, prefixes[i], prefix_length) == 0) {
                json_object_set_new(prefix_variables, var[j].key, json_string(var[j].val));
            }
        }
    }
    if (json_object_size(prefix_variables) == 0) {
        json_decref(prefix_variables);
        prefix_variables = NULL;
    }

    json_t *regex_variables = match_regex_vars(r, cfg->env_regex, variables);
    json_t *result = encode_claims(variables, cfg->env_vars, cfg->send_all_vars, cfg->vars_array_name);

    /* merging all variables into a single JSON */
    if (prefix_variables != NULL || json_variables != NULL || regex_variables != NULL) {
        if (result == NULL) {
            result = json_object();
            json_object_set_new(result, cfg->vars_array_name, json_object());
        }
        json_t *set_envs = json_object_get(result, cfg->vars_array_name);
        if (prefix_variables != NULL) {
            json_object_update_missing_new(set_envs, prefix_variables);
        }
        if (json_variables != NULL) {
            json_object_update_new(set_envs, json_variables);
        }
        if (regex_variables != NULL) {
            json_object_update_missing_new(set_envs, regex_variables);
        }
    }

    if (result != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "Finished setting up environment variables");
    }

    return result;
}

static char *build_json(request_rec *r, const struct config *c)
{
    json_t *request_info = json_object();
    if (request_info == NULL) {
        return NULL;
    }

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
    if (c->filepath_key_name) {
        json_object_set_new(request_info, c->filepath_key_name, json_string(r->filename));
    }
    if (c->version_key_name) {
        json_object_set_new(request_info, c->version_key_name, json_string(r->protocol));
    }
    if (c->auth_key_name) {
        json_object_set_new(request_info, c->auth_key_name, json_string(r->user));
    }
    if (c->query_string != NULL && r->args != NULL) {
        char *q_string = percent_encoding(r->pool, r->args);
        json_object_set_new(request_info, c->query_string, json_string(q_string));
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "Added basic request information to JSON");


    // encoding category data
    json_t *categories[] = { encode_headers(r, c), encode_query_string(r, c),
                 encode_form_fields(r, c), json_deep_copy(c->custom), encode_env_variables(r, c) };

    for (size_t i = 0; i < sizeof(categories) / sizeof(categories[0]); i++) {
        if (categories[i] != NULL) {
            json_object_update_new(request_info, categories[i]);
        }
    }

    json_t *to_send = json_object();
    if (to_send == NULL) {
        json_decref(request_info);
        return NULL;
    }

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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OPA decided to grant access");
        json_decref(decision_json);
        return AUTHZ_GRANTED;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OPA decided to deny access");

    json_decref(decision_json);
    return AUTHZ_DENIED;
}

static authz_status opa_check_authorization(request_rec *r, const char *require_line, const void *parsed_require_line)
{
    const struct config *c = ap_get_module_config(r->per_dir_config, &authz_opa_module);

    // asking for authentication if needed
    if (c->auth_needed && r->user == NULL) {
        return AUTHZ_DENIED_NO_USER;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HTTP request received; preparing to communicate with OPA");

    char *json = build_json(r, c);
    if (json == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to encode request into JSON");
        return AUTHZ_DENIED;
    }

    char *decision = perform_opa_request(r, c, json);
    free(json);
    if (decision == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OPA request failed");
        return HTTP_INTERNAL_SERVER_ERROR;
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
