#include "httpd.h"
#include "http_config.h"

#include <jansson.h>

#include "config.h"

#define DEFAULT_MAX_FORM_SIZE 10000

void *create_dir_configuration(apr_pool_t *p, char *dir)
{
    struct config *c = apr_pcalloc(p, sizeof(struct config));

    c->headers = apr_hash_make(p);
    c->query_string = apr_hash_make(p);
    c->form_fields = apr_hash_make(p);
    c->custom = json_object();

    c->max_form_size = DEFAULT_MAX_FORM_SIZE;
    c->auth_needed = 1;

    return c;
}

void *merge_dir_configuration(apr_pool_t *p, void *base, void *add)
{
    struct config *new = apr_pcalloc(p, sizeof(struct config));
    struct config *b = base;
    struct config *a = add;

    memcpy(new, a, sizeof(struct config));

    new->opa_url = b->opa_url;
    new->opa_decision_grant = b->opa_decision_grant;
    new->max_form_size = b->max_form_size;

    return new;
}

static const char *set_claim_alias(cmd_parms *cmd, void *cfg, const char *key, const char *value)
{
    if (value == NULL) {
        value = key;
    }

    long offset = (long) (cmd->info);
    char *c = cfg;
    apr_hash_t *h = *((apr_hash_t **) (c + offset));
    apr_hash_set(h, key, strlen(key), value);

    return NULL;
}

static const char *set_claim(cmd_parms *cmd, void *cfg, const char *key)
{
    return set_claim_alias(cmd, cfg, key, NULL);
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
        char *copy = strdup(error.text);
        return copy;
    }
    json_object_set_new(c->custom, key, decoded_value);
    return NULL;
}

static const char *set_grant_decision(cmd_parms *cmd, void *cfg, const char *decision)
{
    struct config *c = cfg;
    json_error_t error;
    c->opa_decision_grant = json_loads(decision, 0, &error);
    if (c->opa_decision_grant == NULL) {
        char *copy = strdup(error.text);
        return copy;
    }
    return NULL;
}

static const char *read_decision_file(cmd_parms *cmd, void *cfg, const char *filepath)
{
    json_error_t error;
    struct config *c = cfg;
    c->opa_decision_grant = json_load_file(filepath, 0, &error);
    if (c->opa_decision_grant == NULL) {
        char *copy = strdup(error.text);
        return copy;
    }
    return NULL;
}

const command_rec directives[] = {
    AP_INIT_TAKE1("OpaServerURL", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, opa_url),
              RSRC_CONF, "url representing Opa server"),
    AP_INIT_TAKE1("OpaDecision", set_grant_decision, NULL,
              RSRC_CONF, "json string representing granted authorization"),
    AP_INIT_TAKE1("OpaDecisionFile", read_decision_file, NULL,
              RSRC_CONF, "json file representing granted authorization"),
    AP_INIT_FLAG("OpaAuthNeeded", ap_set_flag_slot, (void *) APR_OFFSETOF(struct config, auth_needed),
              RSRC_CONF, "flag dictating whether user should be prompted to authenticate (on by default)"),

    AP_INIT_ITERATE("OpaHeaderList", set_claim, (void *) APR_OFFSETOF(struct config, headers),
              RSRC_CONF | OR_AUTHCFG, "list of headers to be sent"),
    AP_INIT_TAKE12("OpaHeader", set_claim_alias, (void *) APR_OFFSETOF(struct config, headers),
              RSRC_CONF | OR_AUTHCFG, "header and its alias used for key"),    
    AP_INIT_TAKE1("OpaHeaderArray", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, header_array_name),
              RSRC_CONF | OR_AUTHCFG, "name of the sent header array"),
    AP_INIT_FLAG("OpaSendAllHeaders", ap_set_flag_slot, (void *) APR_OFFSETOF(struct config, send_all_headers),
              RSRC_CONF | OR_AUTHCFG, "flag determining whether all received headers should be sent to OPA"),
    
    AP_INIT_ITERATE("OpaQueryList", set_claim, (void *) APR_OFFSETOF(struct config, query_string),
              RSRC_CONF | OR_AUTHCFG, "list of query string fields to be sent"),
    AP_INIT_TAKE12("OpaQueryString", set_claim_alias, (void *) APR_OFFSETOF(struct config, query_string),
              RSRC_CONF | OR_AUTHCFG, "name of query field to be sent and optionally its alias"),
    AP_INIT_TAKE1("OpaQueryArray", ap_set_string_slot, (void *)APR_OFFSETOF(struct config, query_string_array_name),
              RSRC_CONF | OR_AUTHCFG, "name of the sent query field array"),
    AP_INIT_FLAG("OpaSendAllQueries", ap_set_flag_slot, (void *) APR_OFFSETOF(struct config, send_all_queries),
              RSRC_CONF | OR_AUTHCFG, "flag determining whether all received query fields should be sent to OPA"),

    AP_INIT_ITERATE("OpaFormFieldList", set_claim, (void *) APR_OFFSETOF(struct config, form_fields),
              RSRC_CONF | OR_AUTHCFG, "list of form fields to be sent"),
    AP_INIT_TAKE12("OpaHttpForm", set_claim_alias, (void *) APR_OFFSETOF(struct config, form_fields),
              RSRC_CONF | OR_AUTHCFG, "form field and its alias"),
    AP_INIT_TAKE1("OpaFormDataArray", ap_set_string_slot,(void *) APR_OFFSETOF(struct config,form_field_array_name),
              RSRC_CONF | OR_AUTHCFG, "name of the array to place form data"),
    AP_INIT_FLAG("OpaSendAllFormData", ap_set_flag_slot,(void *) APR_OFFSETOF(struct config, send_all_form_fields),
              RSRC_CONF | OR_AUTHCFG, "flag determining whether all received form fields should be sent to OPA"),

    AP_INIT_TAKE1("OpaFormMaxSize", ap_set_int_slot, (void *) APR_OFFSETOF(struct config, max_form_size),
              RSRC_CONF, "maximum size of the sent request"),
    AP_INIT_TAKE2("OpaCustom", set_custom, (void *) NULL,
              RSRC_CONF | OR_AUTHCFG, "key and a string value for a custom claim"),
    AP_INIT_TAKE2("OpaCustomJson", set_custom_json, (void *) NULL,
              RSRC_CONF | OR_AUTHCFG, "key and a json object or array as value for a custom claim"),

    AP_INIT_TAKE1("OpaRequestIP", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, ip_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for request ip"),
    AP_INIT_TAKE1("OpaRequestHttpVersion", ap_set_string_slot,(void *) APR_OFFSETOF(struct config,version_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the http version"),
    AP_INIT_TAKE1("OpaRequestURL", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, url_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the url"),    
    AP_INIT_TAKE1("OpaRequestMethod", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, method_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the method"),
    AP_INIT_TAKE1("OpaRequestAuth", ap_set_string_slot, (void *) APR_OFFSETOF(struct config, method_key_name),
              RSRC_CONF | OR_AUTHCFG, "name of the key for the authenticated user"),
    { NULL }
};
