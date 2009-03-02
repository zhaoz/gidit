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

struct projdir {
	char * basedir;
	ssize_t pgp_size;
	unsigned char * pgp;
	unsigned char pgp_sha1[20];
	char * userdir;
	char * projdir;
};

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

/*
static void pushobjects_dir(char ** str, const char * base_dir)
{
	*str = (char*)malloc(strlen(PUSHOBJ_DIR) + strlen(base_dir) + 1);
	sprintf(*str, "%s/%s", base_dir, PUSHOBJ_DIR);
}
*/

static void free_projdir(struct projdir* pd)
{
	free(pd->basedir);
	free(pd->pgp);
	free(pd->userdir);
	free(pd->projdir);
	free(pd);
}

static struct projdir* init_projdir(const char * basedir, ssize_t pgp_size, 
		const unsigned char * pgp, const char * projname)
{
	ssize_t bd_size;
	struct projdir * pd = NULL;
	git_SHA_CTX c;
	
	pd = (struct projdir*)malloc(sizeof(struct projdir));
	bd_size = strlen(basedir) + 1; 

	pd->basedir = (char*)malloc(bd_size);
	memcpy(pd->basedir, basedir, bd_size);

	pd->pgp_size = pgp_size;
	pd->pgp = (unsigned char *)malloc(pgp_size);
	memcpy(pd->pgp, pgp, pgp_size);

	git_SHA1_Init(&c);
	git_SHA1_Update(&c, pgp, pgp_size);
	git_SHA1_Final(pd->pgp_sha1, &c);

	// ensure dir existence
	
	pd->userdir = (char*)malloc(strlen(basedir) + 1 + strlen(PUSHOBJ_DIR) + 1
								+ 40 + 1);
	sprintf(pd->userdir, "%s/%s/%s", basedir, PUSHOBJ_DIR, 
			sha1_to_hex(pd->pgp_sha1));
	safe_create_dir(pd->userdir);

	pd->projdir = (char*)malloc(strlen(pd->userdir) + strlen(projname) + 1);
	sprintf(pd->projdir, "%s/%s", pd->userdir, projname);
	safe_create_dir(pd->projdir);


	return pd;
}

int update_pl(FILE *fp, const char * base_dir, unsigned int flags)
{
	struct projdir * pd;
	char pgp_size_raw[5];
	int ch = 0, ii = 0, pgp_size = 0;
	unsigned char *pgp_key = NULL;
	struct strbuf proj_name = STRBUF_INIT;

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

	pgp_key = (unsigned char*)malloc(pgp_size);

	// hash the pgpkey
	if (fread(pgp_key, pgp_size, 1, fp) != 1) {
		fprintf(stderr, "pgpkey error: bad pushobject format\n");
		exit(1);
	}

	// next line is the project name
	if (strbuf_getline(&proj_name, fp, '\n') == EOF) {
		fprintf(stderr, "No projname: bad pushobject format\n");
		exit(1);
	}

	pd = init_projdir(base_dir, pgp_size, pgp_key, proj_name.buf);
	printf("users_dir: %s\n", pd->userdir);
	printf("proj_dir: %s\n", pd->projdir);

	// traverse projectname dir to find stuff


	free(pgp_key);
	free_projdir(pd);
	strbuf_release(&proj_name);

	fclose(fp);

	return 0;
}
