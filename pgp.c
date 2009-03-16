#include "cache.h"
#include "refs.h"
#include "builtin.h"
#include "git-compat-util.h"
#include "pgp.h"

void set_signingkey(const char *value)
{
	if (strlcpy(signingkey, value, sizeof(signingkey)) >= sizeof(signingkey))
		die("signing key value too long (%.10s...)", value);
}

int set_default_signingkey()
{
	if (strlcpy(signingkey, git_committer_info(IDENT_ERROR_ON_NO_NAME),
				sizeof(signingkey)) > sizeof(signingkey) - 1)
		return error("committer info too long.");
	char * bracket = strchr(signingkey, '>');
	if (bracket)
		bracket[1] = '\0';

	return 0;
}
