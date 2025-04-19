all:
	apxs -i -a -c mod_authz_opa.c config.c -lcurl -ljansson
