/*
 * "git gidit"
 */
#include "cache.h"
#include "refs.h"
#include "run-command.h"
#include "builtin.h"
#include "remote.h"
#include "strbuf.h"
#include "transport.h"
#include "gidit.h"

struct gidit_refs_cb_data {
	// FILE *refs_file;
	struct strbuf *buf;
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

	// fprintf(cb->refs_file, "%s %s\n", sha1_to_hex(sha1), path);
	strbuf_addstr(cb->buf, sha1_to_hex(sha1));
	strbuf_addstr(cb->buf, " ");
	strbuf_addstr(cb->buf, path);
	strbuf_addstr(cb->buf, "\n");

	return 0;
}

static int do_sign(struct strbuf *buffer, char * signingkey) {
	struct child_process gpg;
	const char *args[4];
	int len;
	int i, j;

	/* When the username signingkey is bad, program could be terminated
	 * because gpg exits without reading and then write gets SIGPIPE. */
	signal(SIGPIPE, SIG_IGN);

	memset(&gpg, 0, sizeof(gpg));
	gpg.argv = args;
	gpg.in = -1;
	gpg.out = -1;
	args[0] = "gpg";
	args[1] = "-bsau";
	args[2] = signingkey;
	args[3] = NULL;

	if (start_command(&gpg))
		return error("could not run gpg.");

	if (write_in_full(gpg.in, buffer->buf, buffer->len) != buffer->len) {
		close(gpg.in);
		close(gpg.out);
		finish_command(&gpg);
		return error("gpg did not accept the tag data");
	}
	close(gpg.in);
	len = strbuf_read(buffer, gpg.out, 1024);
	close(gpg.out);

	if (finish_command(&gpg) || !len || len < 0)
		return error("gpg failed to sign the tag");

	/* Strip CR from the line endings, in case we are on Windows. */
	for (i = j = 0; i < buffer->len; i++)
		if (buffer->buf[i] != '\r') {
			if (i != j)
				buffer->buf[j] = buffer->buf[i];
			j++;
		}
	strbuf_setlen(buffer, j);

	return 0;
}

int gen_pushobj(FILE *fp, char * signingkey, int sign, unsigned int flags)
{
	const char *head;
	unsigned char head_sha1[21];
	struct gidit_refs_cb_data cbdata;
	struct strbuf buf = STRBUF_INIT;

	cbdata.buf = &buf;
	cbdata.flags = flags;

	head = resolve_ref("HEAD", head_sha1, 0, NULL);
	head_sha1[20] = '\0';
	if (!head)
		die("Failed to resolve HEAD as a valid ref.");
	
	strbuf_add(&buf, sha1_to_hex(head_sha1), 40);
	strbuf_addstr(&buf, " HEAD\n");

	for_each_ref(handle_one_ref, &cbdata);

	if (sign)
		do_sign(&buf, signingkey);

	fprintf(fp, "%s", buf.buf);

	strbuf_release(&buf);
	return 0;
}

static void safe_create_dir(const char *dir)
{
	if (mkdir(dir, 0777) < 0) {
		if (errno != EEXIST) {
			perror(dir);
			exit(1);
		} 

		if (access(dir, W_OK)) {
			fprintf(stderr, "Unable to write to %s\n", dir);
			exit(1);
		}
	}
}

static void create_rel_dir(const char *base, const char *rel)
{
	char *full_path;
	full_path = (char*)malloc(strlen(base) + strlen(rel) + 2);
	sprintf(full_path, "%s/%s", base, rel);
	safe_create_dir(full_path);
	free(full_path);
}

/**
 * initialize a given directory
 */
int gidit_init(const char *path)
{
	safe_create_dir(path);

	// create these dirs if they don't exist
	create_rel_dir(path, BUNDLES_DIR);
	create_rel_dir(path, PUSHOBJ_DIR);

	return 0;
}

int update_pl(FILE *fp, const char * base_dir, unsigned int flags)
{
	struct strbuf pobj_dir = STRBUF_INIT;

	strbuf_addstr(&pobj_dir, "/");
	strbuf_addstr(&pobj_dir, PUSHOBJ_DIR);

	if (access(pobj_dir.buf, W_OK) != 0) {
		fprintf(stderr, "pushbobjects dir was not writable\n");
		exit(1);
	}

	// hash the pgpkey

	// ensure that the directory exists


	strbuf_release(&pobj_dir);

	fclose(fp);

	return 0;
}
