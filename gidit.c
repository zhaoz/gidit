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

static void safe_create_rel_dir(const char *base, const char *rel)
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
	safe_create_rel_dir(path, BUNDLES_DIR);
	safe_create_rel_dir(path, PUSHOBJ_DIR);

	return 0;
}

static void pushobjects_dir(char ** str, const char * base_dir)
{
	*str = (char*)malloc(strlen(PUSHOBJ_DIR) + strlen(base_dir) + 1);
	sprintf(*str, "%s/%s", base_dir, PUSHOBJ_DIR);
}

int update_pl(FILE *fp, const char * base_dir, unsigned int flags)
{
	char *users_dir = NULL;		// base/pushobjects/pgp
	char *pobj_dir = NULL;		// base/pushobjects/
	char *proj_dir = NULL;		// base/pushobjects/pgp/projname
	char pgp_size_raw[5];
	int ch;
	int ii;
	int pgp_size;
	char *pgp_key = NULL;
	struct strbuf proj_name = STRBUF_INIT;
	unsigned char sha1[20];
	char pgp_sha1[41];

	pushobjects_dir(&pobj_dir, base_dir);
	if (access(pobj_dir, W_OK) != 0) {
		fprintf(stderr, "pushbobjects dir was not writable: %s\n", pobj_dir);
		exit(1);
	}

	// read size info in, first 4 bytes
	for (ii = 0; ii < 4; ++ii) {
		ch = fgetc(fp);
		if (ch == EOF) {
			fprintf(stderr, "error while reading size header\n");
			exit(1);
		}
		pgp_size_raw[ii] = ch;
	}
	pgp_size_raw[4] = '\0';
	pgp_size = strtol(pgp_size_raw, (char**)NULL, 16);

	pgp_key = (char*)malloc(pgp_size+1);

	// hash the pgpkey
	if (fread(pgp_key, pgp_size, 1, fp) == 1) {
		// now that we have pgp key, hash it 
		fprintf(stderr, "hashing pgpkey\n");

		pgp_key[pgp_size] = '\0';
		
		git_SHA_CTX c;
		git_SHA1_Init(&c);
		git_SHA1_Update(&c, pgp_key, pgp_size);
		git_SHA1_Final(sha1, &c);

		sprintf(pgp_sha1, "%s", sha1_to_hex(sha1));
		pgp_sha1[40] = '\0';
	} else {
		fprintf(stderr, "pgpkey error: bad pushobject format\n");
		exit(1);
	}

	// next line is the project name
	if (strbuf_getline(&proj_name, fp, '\n') == EOF) {
		fprintf(stderr, "No projname: bad pushobject format\n");
		exit(1);
	}

	// ensure that the users directory exists
	users_dir = (char*)malloc(strlen(pobj_dir) + 40  + 1);
	sprintf(users_dir, "%s/%s", pobj_dir, pgp_sha1);
	printf("users_dir: %s\n", users_dir);
	safe_create_dir(users_dir);

	// ensure that the projectname directory exists
	proj_dir = (char*)malloc(strlen(users_dir) + proj_name.len + 1);
	sprintf(proj_dir, "%s/%s", users_dir, proj_name.buf);
	printf("proj_dir: %s\n", proj_dir);
	safe_create_dir(proj_dir);

	// traverse projectname dir to find stuff


	free(pobj_dir);
	free(proj_dir);
	free(users_dir);
	free(pgp_key);
	strbuf_release(&proj_name);

	fclose(fp);

	return 0;
}
