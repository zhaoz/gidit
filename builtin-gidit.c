/*
 * "git gidit"
 */

#include "cache.h"
#include "refs.h"
#include "run-command.h"
#include "builtin.h"
#include "remote.h"
#include "transport.h"
#include "parse-options.h"
#include "pgp.h"
#include "gidit.h"

static const char * const gidit_usage[] = {
	"git gidit [-s|-u <key-id>] [--tags] --pushobj",
	"git gidit -b <base_dir> --init",
	"echo <projname>\\n<PGP> | git gidit -b <base_dir> --proj-init",
	"echo <PGPSHA1><proj>\\n<pushobj> | git gidit -b <base-path> --updatepl",
	"echo <PGPSHA1><proj> | git gidit -b <base-path> --polist",
	"echo <SHA1 Pobj Start><SHA1 Pobj End> | git gidit -b <base-path> --get-bundle",
	"echo <SHA1 Pobj Start><SHA1 Pobj End><bundle> | git gidit -b <base-path> --store-bundle",
	"echo <pushobj> | git gidit --verify-pobj",
	NULL,
};

static int git_gidit_config(const char *var, const char *value, void *cb)
{
	if (!strcmp(var, "user.signingkey")) {
		if (!value)
			return config_error_nonbool(var);
		set_signingkey(value);
		return 0;
	}

	return git_default_config(var, value, cb);
}

/**
 * Test basepath existence and is absolute
 */
static int base_path_test(const char * basepath)
{
	if (!basepath) {
		return error("Need basepath.");
	}
	if (*basepath != '/') {
		/* Allow only absolute */
		return error("'%s': Non-absolute path denied (base-path active)",
				basepath);
	}
	return 0;
}

int cmd_gidit(int argc, const char **argv, const char *prefix)
{
	int flags = 0;
	int init = 0, verbose = 0, pushobj = 0, updatepl = 0, sign = 0,
		proj_init = 0, polist = 0, store_bundle = 0, get_bundle = 0, pobj_val = 0,
		create_bundle = 0, push = 0, verify_polist = 0, list_missing = 0, test = 0;

	const char *basepath = NULL;
	const char *keyid = NULL;
	const char *projname = NULL;
	char * url = NULL;
	char *nodekey = NULL;
	char *message = NULL;

	int rc;

	struct option options[] = {
		OPT__VERBOSE(&verbose),
		OPT_GROUP(""),
		OPT_BIT( 0 , "tags", &flags, "include tags", INCLUDE_TAGS),
		OPT_BIT( 0 , "force", &flags, "force", TRANSPORT_PUSH_FORCE),
		OPT_BOOLEAN('s', NULL, &sign, "annotated and GPG-signed tag"),
		OPT_STRING('u', NULL, &keyid, "key-id",
					"use another key to sign the tag"),
		OPT_BOOLEAN( 0 , "pushobj", &pushobj, "generate push object"),
		OPT_STRING('k',NULL, &nodekey, "nodekey", "key of node"),
		OPT_STRING('m',NULL, &message, "message", "message to send"),
		OPT_STRING('p',NULL, &projname, "project-name", "Project name"),
		OPT_BOOLEAN( 0 , "verify-pobj", &pobj_val, "validate a given pushobject"),
		OPT_BOOLEAN( 0 , "verify-polist", &verify_polist, "verify given polist as all known"),
		OPT_BOOLEAN( 0 , "test", &test, "test some function"),
		OPT_BOOLEAN( 0 , "list-missing", &list_missing, "List sha1's of missing pushobjs"),
		OPT_BOOLEAN( 0 , "push", &push, "Do a push over gidit"),
		OPT_BOOLEAN( 0 , "create-bundle", &create_bundle, 
					"validate a given pushobject"),
		OPT_GROUP(""),
		OPT_BOOLEAN( 0 , "updatepl", &updatepl, "Update push list"),
		OPT_STRING('b', NULL, &basepath, "base-path", "base-path for daemon"),
		OPT_BOOLEAN( 0 , "init", &init, "init gidit directory"),
		OPT_BOOLEAN( 0 , "proj-init", &proj_init, 
					"init user's gidit project directory"),
		OPT_BOOLEAN( 0 , "polist", &polist, "Generate list of push objects"),
		OPT_BOOLEAN( 0 , "store-bundle", &store_bundle, "store a given bundle"),
		OPT_BOOLEAN( 0 , "get-bundle", &get_bundle, "get a bundle"),
		OPT_END()
	};

	git_config(git_gidit_config, NULL);

	argc = parse_options(argc, argv, options, gidit_usage, 0);

	if (push)
		sign = 1;

	if (keyid) {
		sign = 1;
		set_signingkey(keyid);
	} else if (sign) {
		set_default_signingkey();
	}

	if (sign)
		flags |= SIGN;

	if (pushobj)
		return !!gidit_pushobj(stdout, signingkey, flags);
	else if (pobj_val)
		return !!gidit_verify_pushobj(stdin, flags);
	else if (pushobj)
		return !!gidit_pushobj(stdout, signingkey, flags);
	else if (create_bundle)
		return !!gidit_gen_bundle(stdin, flags);
	else if (verify_polist)
		return !!gidit_verify_pushobj_list(stdin);
	else if (list_missing)
		return !!gidit_missing_pushobjs(stdin);
	else if (test)
		return !!gidit_test(stdin);
	else if (push) {
		url = (char*)malloc(strlen("gidit://127.0.0.1:9418/") + 
				strlen(projname) + 1 + strlen(signingkey) + 1);
		sprintf(url, "gidit://127.0.0.1:9418/%s:%s", projname, signingkey);
		return !!gidit_push(url, 0, NULL, flags);
	}

	if (!basepath)
		usage_with_options(gidit_usage, options);

	if (base_path_test(basepath))
		return -1;

	if (init)
		rc = gidit_init(basepath);
	else if (proj_init)
		rc = gidit_proj_init_stream(stdin, basepath, flags);
	else if (updatepl)
		rc = gidit_update_pl(stdin, basepath, flags);
	else if (polist)
		rc = gidit_po_list_stream(stdin, basepath, flags);
	else if (store_bundle)
		rc = gidit_store_bundle_stream(stdin, basepath, flags);
	else if (get_bundle)
		rc = gidit_get_bundle(stdin, stdout, basepath, flags);
	else
		rc = -1;

	if (rc == -1)
		usage_with_options(gidit_usage, options);
	else
		return rc;
}
