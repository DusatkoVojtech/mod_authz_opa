# mod_authz_opa

This is an Apache webserver authorization module with the decision making delegated into Open Policy Agent. It encodes data from the HTTP request into JSON and sends them to the OPA server.

## Dependencies

**libcurl:** https://curl.se/libcurl
**libjansson:** https://github.com/akheron/jansson

The module can be installed and activated by running the apxs tool:
```apache
apxs -i -a -c mod_authz_opa.c config.c -lcurl -ljansson
```

## Usage

The module needs to be loaded by the Apache web server. It handles authorization for those directories where the directive 'Require opa' has been set.

It is necessary to specify the URL (including the port number) of the OPA server using the OpaServerUrl directive. You also have to set the OpaDecision directive to the path to the boolean value in the OPA response JSON, which determines whether to grant auhorization.

By default the module sends an empty JSON object. You need to configure what data is to be sent using Apache directives. The directives are documented at the end of the config.c file.

You can choose the names of the keys under which the data will be sent. Many attributes are activated by simply declaring the directive and the name of the key. Category data (such as HTTP headers) can be defined one by one or they can all be sent together. It is also possible to define additional custom data.
