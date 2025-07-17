# Directives

OPA authorization can be activated for a given location using the directive **Require opa**.

## Scope

All configuration directives can be placed anywhere in the config file or directive containers (including Directory, Location, VirtualHost). The effect of the directive is inherited to the subdirectories and possibly merged with new declarations. The directives can also be placed in .htaccess files if the directive for the directory of the .htaccess file is configured with AllowOverride AuthConfig.

## General

**OpaServerURL** url - url path to the opa server, including the port and path (default: http://localhost:8181/)

**OpaDecision** path - key path to the boolean value in OPA response - keys are separated by '/' characters (default: result/allow)

The following directives will tell the module to place their data into the output JSON. Unlike the category directives, these won't be placed in an array.

**OpaRequestIP** key_name - makes the module send the IP address of the request to OPA

**OpaRequestHttpVersion** key_name - makes the module send HTTP version of the request to OPA

**OpaRequestURL** key_name - makes the module send the client requested URL to OPA

**OpaFilePath** key_name - makes the module send the name of the target resource to OPA

**OpaRequestMethod** key_name - makes the module send name of the HTTP method of the request to OPA

**OpaRemoteUser** key_name - makes the module send the name of the authenticated user to OPA

## Flag directives

These directives represent flags which can be simply set on or off by specifying either "on" or "off" in the argument. They each have a default value if not declared.

**OpaAuthNeeded** - dictates whether the client should be required to authenticate prior to auhorization (default: on)

**OpaSendAllHeaders**, **OpaSendAllFormData**, **OpaSendAllVars** - tells the module to send all available data of the given category (default: off)

**OpaQueryParameters** - makes the module parse the query string parameters into separate fields before sending them to OPA (default: off)

## Header directives

These directives determine which HTTP request headers should be sent to OPA.

**OpaHeadersList** header1 header2 header3 ... - makes the module send the listed headers to OPA

**OpaHeader** name [alias] - makes the module send this header to OPA, optionally under an alias

**OpaHeadersArray** array - specifies the name of the array under which the headers should be sent (default: headers)

**OpaSendHeaderJSON** header1 header2 header3 ... - specifies that the values of these headers are JSON objects or arrays and should be sent to OPA directly

## QueryString directives

These directives specify how the HTTP query string should be sent to OPA.

**OpaQueryString** key_name - tells the module to send the unparsed query string under the key "key_name"

**OpaQueryList** param1 param2 param3 ... - if OpaQueryParameters is set, this limits the sent query parameters to this list

**OpaQueryArray** array - specifies the name of the array under which the parsed query parameters are sent - this applies if OpaQueryParameters is set (default: query_string)

## Form data directives

If the request carries in its body "application/x-www-form-urlencoded" data, these directives determine which of the fields should be sent to OPA.

**OpaFormFieldList** field1 field2 field3 ... - list of fields which should be sent to OPA

**OpaHttpForm** field [alias] - field and its optional alias which the module will send to OPA

**OpaFormDataArray** array - name of the array under which the module will send the fields (default: form_data)

**OpaFormMaxSize** size - maximum size in bytes of the received request body for the form fields to be processed (default: 10000)

## Environment vars directives

These directives decide which of the environment variables should be sent to OPA and how. These variables are internal Apache httpd variables, which are set by other modules. They are not related to the environment variables of the process.

**OpaSendVarsList** var1 var2 var3 ... - makes the module send these variables to OPA

**OpaSendVar** name [alias] - makes the module send this variable to OPA (the alias is optional)

**OpaSendVarsWithPrefix** - prefix1 prefix2 prefix3 ... - sends all variables which begin with one of the listed prefixes

**OpaSendVarsMatching** regex1 regex2 regex3 ... - sends all variables which match one of the listed regular expressions (the expressions are POSIX extended regular expression)

**OpaSendVarsArray** array - specifies the name of the array under which the variables should be sent (default: vars)

**OpaSendVarJSON** var1 var2 var3 ... - specifies that the values of these variables are JSON objects or arrays and should be sent to OPA directly

## Custom

These directives can be used to add additional custom claims, that will always be sent alongside all the other data. The claims won't be palced in an array.

**OpaCustom** key value - makes the module send field "key" with value "value" to OPA regardless of HTTP request contents

**OpaCustomJson** key value - same as OpaCustom, but the value will be interpreted as JSON and needs to be a valid JSON object or array
