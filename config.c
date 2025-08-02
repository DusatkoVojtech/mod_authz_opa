#include "httpd.h"
#include "http_config.h"
#include "apr_strings.h"
#include "apr_lib.h"

#include <jansson.h>

#include "config.h"

#define FLAG_UNSET 2

const char *DEFAULT_OPA_URL = "http://localhost:8181/";
const int DEFAULT_MAX_FORM_SIZE = 10000;
const char *DEFAULT_HEADERS_ARRAY_NAME = "headers";
const char *DEFAULT_QUERY_STRING_ARRAY_NAME = "query_string";
const char *DEFAULT_FORM_DATA_ARRAY_NAME = "form_data";
const char *DEFAULT_VARIABLES_ARRAY_NAME = "vars";

char *DEFAULT_OPA_DECISION[] = { "result", "allow", NULL };

static apr_status_t cleanup_json(void *arg)
{
    json_decref(arg);
    return APR_SUCCESS;
}

void *create_dir_configuration(apr_pool_t *p, char *dir)
{
    struct config *c = apr_pcalloc(p, sizeof(struct config));

    c->opa_url = DEFAULT_OPA_URL;
    c->opa_decision_grant = DEFAULT_OPA_DECISION;

    c->headers = apr_hash_make(p);
    c->query_parameters = apr_hash_make(p);
    c->form_fields = apr_hash_make(p);
    c->env_vars = apr_hash_make(p);

    c->env_prefixes = apr_array_make(p, APR_DATA_STRUCT_SIZE, sizeof(char *));
    c->json_env = apr_array_make(p, APR_DATA_STRUCT_SIZE, sizeof(char *));
    c->json_headers = apr_array_make(p, APR_DATA_STRUCT_SIZE, sizeof(char *));
    c->env_regex = apr_array_make(p, APR_DATA_STRUCT_SIZE, sizeof(ap_regex_t *));

    c->headers_array_name = DEFAULT_HEADERS_ARRAY_NAME;
    c->query_string_array_name = DEFAULT_QUERY_STRING_ARRAY_NAME;
    c->form_data_array_name = DEFAULT_FORM_DATA_ARRAY_NAME;
    c->vars_array_name = DEFAULT_VARIABLES_ARRAY_NAME;

    c->custom = json_object();
    apr_pool_cleanup_register(p, NULL, cleanup_json, apr_pool_cleanup_null);

    c->max_form_size = DEFAULT_MAX_FORM_SIZE;
    c->auth_needed = 2;

    return c;
}

void *merge_dir_configuration(apr_pool_t *p, void *base, void *add)
{
    struct config *new = apr_pcalloc(p, sizeof(struct config));
    struct config *b = base;
    struct config *a = add;

    memcpy(new, a, sizeof(struct config));

    if (new->opa_url == DEFAULT_OPA_URL) new->opa_url = b->opa_url;
    if (new->opa_decision_grant == DEFAULT_OPA_DECISION) new->opa_decision_grant = b->opa_decision_grant;
    if (new->auth_needed == FLAG_UNSET) new->auth_needed = b->auth_needed;
    if (new->ip_key_name == NULL) new->ip_key_name = b->ip_key_name;
    if (new->method_key_name == NULL) new->method_key_name = b->method_key_name;
    if (new->version_key_name == NULL) new->version_key_name = b->version_key_name;
    if (new->url_key_name == NULL) new->url_key_name = b->url_key_name;
    if (new->filepath_key_name == NULL) new->filepath_key_name = b->filepath_key_name;
    if (new->auth_key_name == NULL) new->auth_key_name = b->auth_key_name;
    if (new->query_string == NULL) new->query_string = b->query_string;

    new->headers = apr_hash_overlay(p, a->headers, b->headers);
    new->query_parameters = apr_hash_overlay(p, a->query_parameters, b->query_parameters);
    new->form_fields = apr_hash_overlay(p, a->form_fields, b->form_fields);
    new->env_vars = apr_hash_overlay(p, a->env_vars, b->env_vars);

    new->env_prefixes = apr_array_append(p, b->env_prefixes, a->env_prefixes);
    new->json_headers = apr_array_append(p, b->json_headers, a->json_headers);
    new->json_env = apr_array_append(p, b->json_env, a->json_env);
    new->env_regex = apr_array_append(p, b->env_regex, a->env_regex);

    if (new->headers_array_name == DEFAULT_HEADERS_ARRAY_NAME) new->headers_array_name = b->headers_array_name;
    if (new->query_string_array_name == DEFAULT_QUERY_STRING_ARRAY_NAME) {
        new->query_string_array_name = b->query_string_array_name;
    }
    if (new->form_data_array_name == DEFAULT_FORM_DATA_ARRAY_NAME) new->form_data_array_name = b->form_data_array_name;
    if (new->vars_array_name == DEFAULT_VARIABLES_ARRAY_NAME) new->vars_array_name = b->vars_array_name;

    if (!new->headers_flag_set) {
        new->send_all_headers = b->send_all_headers;
        new->headers_flag_set = b->headers_flag_set;
    }
    if (!new->query_flag_set) {
        new->parse_query_string = b->parse_query_string;
        new->query_flag_set = b->query_flag_set;
    }
    if (!new->form_flag_set) {
        new->send_all_form_fields = b->send_all_form_fields;
        new->form_flag_set = b->form_flag_set;
    }
    if (!new->vars_flag_set) {
        new->send_all_vars = b->send_all_vars;
        new->vars_flag_set = b->vars_flag_set;
    }
    if (!new->max_form_set) {
        new->max_form_size = b->max_form_size;
        new->max_form_set = b->max_form_set;
    }

    new->custom = json_object();
    json_object_update(new->custom, b->custom);
    json_object_update(new->custom, a->custom);
    apr_pool_cleanup_register(p, NULL, cleanup_json, apr_pool_cleanup_null);

    return new;
}

static const char *set_claim_alias(cmd_parms *cmd, void *cfg, const char *key, const char *value)
{
    long offset = (long) cmd->info;
    char *c = cfg;
    apr_hash_t *h = *((apr_hash_t **) (c + offset));

    if (apr_hash_get(h, key, strlen(key)) != NULL && value == NULL) {
        return NULL;
    }
    if (value == NULL) {
        value = key;
    }
    apr_hash_set(h, key, strlen(key), value);

    return NULL;
}

static const char *set_claim(cmd_parms *cmd, void *cfg, const char *key)
{
    return set_claim_alias(cmd, cfg, key, NULL);
}

static const char *add_array_element(cmd_parms *cmd, void *cfg, const char *name)
{
    char *c = cfg;
    long offset = (long) cmd->info;
    apr_array_header_t *array = *((apr_array_header_t **) (c + offset));
    const void **new = apr_array_push(array);
    *new = name;

    return NULL;
}

static const char *add_regex(cmd_parms *cmd, void *cfg, const char *pattern)
{
    ap_regex_t *regex = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED);
    if (regex == NULL) {
        return apr_psprintf(cmd->pool, "Couldn't compile pattern %s", pattern);
    }

    return add_array_element(cmd, cfg, (void *) regex);
}

static const char *set_custom(cmd_parms *cmd, void *cfg, const char *key, const char *value)
{
    struct config *c = cfg;
    json_object_set_new(c->custom, key, json_string(value));
    return NULL;
}

static const char *set_custom_json(cmd_parms *cmd, void *cfg, const char *key, const char *json_value)
{
    struct config *c = cfg;
    json_error_t error;
    json_t *decoded_value = json_loads(json_value, 0, &error);
    if (decoded_value == NULL) {
        char *copy = apr_pstrdup(cmd->pool, error.text);
        return copy;
    }
    json_object_set_new(c->custom, key, decoded_value);
    return NULL;
}

static const char *set_grant_decision(cmd_parms *cmd, void *cfg, const char *arg)
{
    char *decision = apr_pstrdup(cmd->pool, arg);
    char *next;
    int count = 0;
    char **path = apr_palloc(cmd->pool, strlen(decision) * sizeof(char *));

    for (char *token = apr_strtok(decision, "/", &next); token != NULL; token = apr_strtok(NULL, "/", &next)) {
        for (int i = 0; token[i] != '\0'; i++) {
            if (apr_isspace(token[i])) {
                return "Invalid OpaDecision path";
            }
        }
        path[count] = token;
        count++;
    }
    path[count] = NULL;

    struct config *c = cfg;
    c->opa_decision_grant = path;

    return NULL;
}

static const char *set_max_form(cmd_parms *cmd, void *cfg, const char *max)
{
    struct config *c = cfg;
    c->max_form_set = 1;
    return ap_set_int_slot(cmd, cfg, max);
}

static const char *set_headers_flag(cmd_parms *cmd, void *cfg, int flag)
{
    struct config *c = cfg;
    c->send_all_headers = flag;
    c->headers_flag_set = 1;
    return NULL;
}

static const char *set_query_flag(cmd_parms *cmd, void *cfg, int flag)
{
    struct config *c = cfg;
    c->parse_query_string = flag;
    c->query_flag_set = 1;
    return NULL;
}

static const char *set_form_flag(cmd_parms *cmd, void *cfg, int flag)
{
    struct config *c = cfg;
    c->send_all_form_fields = flag;
    c->form_flag_set = 1;
    return NULL;
}

static const char *set_vars_flag(cmd_parms *cmd, void *cfg, int flag)
{
    struct config *c = cfg;
    c->send_all_vars = flag;
    c->vars_flag_set = 1;
    return NULL;
}

const command_rec directives[] = {
    AP_INIT_TAKE1("OpaServerURL", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, opa_url),
              RSRC_CONF | OR_AUTHCFG, "url representing Opa server"),
    AP_INIT_TAKE1("OpaDecision", set_grant_decision, NULL,
              RSRC_CONF | OR_AUTHCFG, "path of keys to a key with boolean value in response (keys are separated by / characters)"),
    AP_INIT_FLAG("OpaAuthNeeded", ap_set_flag_slot, (void *) APR_OFFSETOF(struct config, auth_needed),
              RSRC_CONF | OR_AUTHCFG, "flag dictating whether user should be prompted to authenticate (on by default)"),

    AP_INIT_ITERATE("OpaHeadersList", set_claim, (void *) APR_OFFSETOF(struct config, headers),
              RSRC_CONF | OR_AUTHCFG, "list of headers to be sent"),
    AP_INIT_TAKE12("OpaHeader", set_claim_alias, (void *) APR_OFFSETOF(struct config, headers),
              RSRC_CONF | OR_AUTHCFG, "header and its alias used for key"),    
    AP_INIT_TAKE1("OpaHeadersArray", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, headers_array_name),
              RSRC_CONF | OR_AUTHCFG, "name of the sent header array"),
    AP_INIT_FLAG("OpaSendAllHeaders", set_headers_flag, NULL,
              RSRC_CONF | OR_AUTHCFG, "flag determining whether all received headers should be sent to OPA"),
    AP_INIT_ITERATE("OpaSendHeaderJSON", add_array_element, (void *) APR_OFFSETOF(struct config, json_headers),
              RSRC_CONF | OR_AUTHCFG, "name of a header which contains a JSON value"),

    AP_INIT_TAKE1("OpaQueryString", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, query_string),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the unparsed query string"),
    AP_INIT_FLAG("OpaQueryParameters", set_query_flag, NULL,
              RSRC_CONF | OR_AUTHCFG, "flag determining whether the module should attempt to parse the query string"),
    AP_INIT_ITERATE("OpaQueryList", set_claim, (void *) APR_OFFSETOF(struct config, query_parameters),
              RSRC_CONF | OR_AUTHCFG, "list of query string fields to be sent (all fields are sent if not declared)"),
    AP_INIT_TAKE1("OpaQueryArray", ap_set_string_slot, (void *)APR_OFFSETOF(struct config, query_string_array_name),
              RSRC_CONF | OR_AUTHCFG, "name of the array containing the parsed query parameters"),

    AP_INIT_ITERATE("OpaFormFieldList", set_claim, (void *) APR_OFFSETOF(struct config, form_fields),
              RSRC_CONF | OR_AUTHCFG, "list of form fields to be sent"),
    AP_INIT_TAKE12("OpaHttpForm", set_claim_alias, (void *) APR_OFFSETOF(struct config, form_fields),
              RSRC_CONF | OR_AUTHCFG, "form field and its alias"),
    AP_INIT_TAKE1("OpaFormDataArray", ap_set_string_slot, (void *) APR_OFFSETOF(struct config,form_data_array_name),
              RSRC_CONF | OR_AUTHCFG, "name of the array to place form data"),
    AP_INIT_FLAG("OpaSendAllFormData", set_form_flag, NULL,
              RSRC_CONF | OR_AUTHCFG, "flag determining whether all received form fields should be sent to OPA"),

    AP_INIT_ITERATE("OpaSendVarsList", set_claim, (void *) APR_OFFSETOF(struct config, env_vars),
            RSRC_CONF | OR_AUTHCFG, "list of environment variables to be sent"),
    AP_INIT_TAKE12("OpaSendVar", set_claim_alias, (void *) APR_OFFSETOF(struct config, env_vars),
            RSRC_CONF | OR_AUTHCFG, "name of an environment variable to be sent and its optional alias"),
    AP_INIT_ITERATE("OpaSendVarsWithPrefix", add_array_element, (void *) APR_OFFSETOF(struct config, env_prefixes),
            RSRC_CONF | OR_AUTHCFG, "prefix of environment variables to be sent to OPA"),
    AP_INIT_ITERATE("OpaSendVarsMatching", add_regex, (void *) APR_OFFSETOF(struct config, env_regex),
            RSRC_CONF | OR_AUTHCFG, "string matching variables which should be sent ot OPA"),
    AP_INIT_TAKE1("OpaVarsArray", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, vars_array_name),
            RSRC_CONF | OR_AUTHCFG, "name of the array to place environment variables"),
    AP_INIT_FLAG("OpaSendAllVars", set_vars_flag, NULL,
              RSRC_CONF | OR_AUTHCFG, "flag determining whether all environment variables should be sent to OPA"),
    AP_INIT_ITERATE("OpaSendVarJSON", add_array_element, (void *) APR_OFFSETOF(struct config, json_env),
              RSRC_CONF | OR_AUTHCFG, "name of a variable which contains a JSON value"),

    AP_INIT_TAKE1("OpaFormMaxSize", set_max_form, (void *) APR_OFFSETOF(struct config, max_form_size),
              RSRC_CONF | OR_AUTHCFG, "maximum size of the sent request"),
    AP_INIT_TAKE2("OpaCustom", set_custom, (void *) NULL,
              RSRC_CONF | OR_AUTHCFG, "key and a string value for a custom claim"),
    AP_INIT_TAKE2("OpaCustomJSON", set_custom_json, (void *) NULL,
              RSRC_CONF | OR_AUTHCFG, "key and a json object or array as value for a custom claim"),

    AP_INIT_TAKE1("OpaRequestIP", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, ip_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for request ip"),
    AP_INIT_TAKE1("OpaRequestHttpVersion", ap_set_string_slot,(void *) APR_OFFSETOF(struct config,version_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the http version"),
    AP_INIT_TAKE1("OpaRequestURL", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, url_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the url"),
    AP_INIT_TAKE1("OpaFilePath", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, filepath_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the filepath"),
    AP_INIT_TAKE1("OpaRequestMethod", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, method_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the method"),
    AP_INIT_TAKE1("OpaRemoteUser", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, auth_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the authenticated user"),
    { NULL }
};
