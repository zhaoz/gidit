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
	"git gidit [-s|-u <key-id>] [[[--tags] --pushobj] | [-b <base_dir> --updatepl] | [--send -k <key> -m <message>]",
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
	int tags = 0, pushobj = 0, updatepo = 0, sign = 0, send=0;

	const char *base_dir;
	const char *keyid;
	const char *nodekey;
	const char *message;

	int rc;

	struct option options[] = {
		OPT_BIT('v', "verbose", &flags, "be verbose", TRANSPORT_PUSH_VERBOSE),
		OPT_BOOLEAN( 0 , "tags", &tags, "include tags"),
		OPT_BOOLEAN('s', NULL, &sign, "annotated and GPG-signed tag"),
		OPT_STRING('u', NULL, &keyid, "key-id",
					"use another key to sign the tag"),
		OPT_BOOLEAN( 0 , "pushobj", &pushobj, "generate push object"),
		OPT_BOOLEAN( 0 , "send", &send, "send message to other node"),
		OPT_BOOLEAN( 0 , "updatepl", &updatepo, "Update push list"),
		OPT_STRING('k',NULL, &nodekey, "nodekey", "key of node"),
		OPT_STRING('m',NULL, &message, "message", "message to send"),
		OPT_STRING('b', NULL, &base_dir, "base_dir", "base_dir for daemon"),
		OPT_END()
	};

	git_config(git_gidit_config, NULL);

	argc = parse_options(argc, argv, options, gidit_usage, 0);

	if (keyid) {
		sign = 1;
		set_signingkey(keyid);
	} else {
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
	
	if (send)
		rc = send_message(nodekey, message);

	else
		rc = -1;

	if (rc == -1)
		usage_with_options(gidit_usage, options);
	else
		return rc;
}
