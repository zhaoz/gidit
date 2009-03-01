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
	"git gidit -b <base-path> --updatepl",
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

int cmd_gidit(int argc, const char **argv, const char *prefix)
{
	int flags = 0;
	int tags = 0, init = 0, verbose = 0, pushobj = 0, updatepl = 0, sign = 0;

	const char *basepath = NULL;
	const char *keyid = NULL;

	int rc;

	struct option options[] = {
		OPT__VERBOSE(&verbose),
		OPT_GROUP(""),
		OPT_BOOLEAN( 0 , "tags", &tags, "include tags"),
		OPT_BOOLEAN('s', NULL, &sign, "annotated and GPG-signed tag"),
		OPT_STRING('u', NULL, &keyid, "key-id",
					"use another key to sign the tag"),
		OPT_BOOLEAN( 0 , "pushobj", &pushobj, "generate push object"),
		OPT_BOOLEAN( 0 , "init", &init, "init gidit directory"),
		OPT_GROUP(""),
		OPT_BOOLEAN( 0 , "updatepl", &updatepl, "Update push list"),
		OPT_STRING('b', NULL, &basepath, "base-path", "base-path for daemon"),
		OPT_END()
	};

	git_config(git_gidit_config, NULL);

	argc = parse_options(argc, argv, options, gidit_usage, 0);

	if (keyid) {
		sign = 1;
		set_signingkey(keyid);
	} else if (sign) {
		if (strlcpy(signingkey, git_committer_info(IDENT_ERROR_ON_NO_NAME),
				sizeof(signingkey)) > sizeof(signingkey) - 1)
			return error("committer info too long.");
		char * bracket = strchr(signingkey, '>');
		if (bracket)
			bracket[1] = '\0';
	}

	if (tags)
		flags |= INCLUDE_TAGS;

	if (pushobj) 
		rc = gen_pushobj(stdout, signingkey, sign, flags);
	else if (init) {
		if (!basepath) {
			fprintf(stderr, "Need to give a basepath to init\n");
			exit(1);
		}
		rc = gidit_init(basepath);
	} else if (updatepl) {
		if (!basepath)
			return error("Need base dir with updatepl.");
		if (*basepath != '/') {
			/* Allow only absolute */
			fprintf(stderr, "'%s': Non-absolute path denied (base-path active)",
				basepath);
			return -1;
		}
		rc = update_pl(stdout, basepath, flags);
	} else
		rc = -1;

	if (rc == -1)
		usage_with_options(gidit_usage, options);
	else
		return rc;
}
