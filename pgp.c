#include "git-compat-util.h"
#include "pgp.h"

void set_signingkey(const char *value)
{
	if (strlcpy(signingkey, value, sizeof(signingkey)) >= sizeof(signingkey))
		die("signing key value too long (%.10s...)", value);
}
