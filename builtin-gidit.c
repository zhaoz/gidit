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
#include "gidit.h"

static const char * const gidit_usage[] = {
	"git gidit [--tags] --pushobj",
	NULL,
};

int cmd_gidit(int argc, const char **argv, const char *prefix)
{
	int flags = 0;
	int tags = 0;
	int pushobj = 0;
	int rc;
	const char *repo = NULL;	/* default repository */

	struct option options[] = {
		OPT_BIT('v', "verbose", &flags, "be verbose", TRANSPORT_PUSH_VERBOSE),
		OPT_BOOLEAN( 0 , "tags", &tags, "include tags"),
		OPT_BOOLEAN( 0 , "pushobj", &pushobj, "generate push object"),
		OPT_END()
	};

	argc = parse_options(argc, argv, options, gidit_usage, 0);

	if (tags)
		flags |= INCLUDE_TAGS;

	if (pushobj) {
		rc = gen_pushobj(stdout, flags);
	} else {
		rc = -1;
	}

	if (rc == -1)
		usage_with_options(gidit_usage, options);
	else
		return rc;
}
