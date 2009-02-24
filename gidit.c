/*
 * "git gidit"
 */
#include "cache.h"
#include "refs.h"
#include "run-command.h"
#include "builtin.h"
#include "remote.h"
#include "transport.h"
#include "gidit.h"

struct gidit_refs_cb_data {
	FILE *refs_file;
	unsigned int flags;
};

static int handle_one_ref(const char *path, const unsigned char *sha1,
			  int flags, void *cb_data) {
	struct gidit_refs_cb_data *cb = cb_data;
	int is_tag_ref;

	/* ignore symbolic refs */
	if ((flags & REF_ISSYMREF))
		return 0;

	is_tag_ref = !prefixcmp(path, "refs/tags/");

	// ignore tags and remotes
	if ((is_tag_ref && !(cb->flags & INCLUDE_TAGS)) 
			|| !prefixcmp(path, "refs/remotes/")
			|| !prefixcmp(path, "refs/stash"))
		return 0;

	fprintf(cb->refs_file, "%s %s\n", sha1_to_hex(sha1), path);

	return 0;
}

int gen_pushobj(FILE *fp, unsigned int flags)
{
	// struct commit *rev, *head_rev = head_rev;
	const char *head;
	unsigned char head_sha1[20];
	struct gidit_refs_cb_data cbdata;

	cbdata.refs_file = fp;
	cbdata.flags = flags;

	head = resolve_ref("HEAD", head_sha1, 0, NULL);
	if (!head)
		die("Failed to resolve HEAD as a valid ref.");

	fprintf(fp, "%s HEAD\n", sha1_to_hex(head_sha1));

	for_each_ref(handle_one_ref, &cbdata);

	return 0;
}
