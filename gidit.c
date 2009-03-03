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
#include "pgp.h"
#include "gidit.h"

struct projdir {
	char * basedir;
	int pgp_len;
	unsigned char * pgp;
	unsigned char pgp_sha1[20];
	char * userdir;
	char * projdir;
	char head[41];
};

struct gidit_refs_cb_data {
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

int gidit_pushobj(FILE *fp, char * signingkey, int sign, unsigned int flags)
{
	const char *head;
	unsigned char head_sha1[21];
	struct gidit_refs_cb_data cbdata;
	struct strbuf buf = STRBUF_INIT;

	cbdata.buf = &buf;
	cbdata.flags = flags;

	head = resolve_ref("HEAD", head_sha1, 0, NULL);
	head_sha1[20] = '\0';
	if (!head) {
		strbuf_release(&buf);
		return error("Failed to resolve HEAD as a valid ref.");
	}
	
	strbuf_add(&buf, sha1_to_hex(head_sha1), 40);
	strbuf_addstr(&buf, " HEAD\n");

	for_each_ref(handle_one_ref, &cbdata);

	if (sign)
		do_sign(&buf, signingkey);

	if (fwrite(buf.buf, buf.len, 1, fp) != 1) {
		strbuf_release(&buf);
		return error("Error while writing pushobj");
	}

	strbuf_release(&buf);
	return 0;
}

static int safe_create_dir(const char *dir)
{
	if (mkdir(dir, 0777) < 0) {
		if (errno != EEXIST) {
			perror(dir);
			return error("Error while making directory");
		} 

		if (access(dir, W_OK)) {
			return error("Unable to write to directory");
		}
	}

	return 0;
}

static int safe_create_rel_dir(const char *base, const char *rel)
{
	char *full_path;
	int rc = 0;
	full_path = (char*)malloc(strlen(base) + strlen(rel) + 2);
	sprintf(full_path, "%s/%s", base, rel);
	rc = safe_create_dir(full_path);
	free(full_path);
	return rc;
}

/**
 * initialize a given directory
 */
int gidit_init(const char *path)
{
	int rc = 0;
	if ((rc = safe_create_dir(path)))
		return rc;

	// create these dirs if they don't exist
	if ((rc = safe_create_rel_dir(path, BUNDLES_DIR)) == 0 && 
		(rc = safe_create_rel_dir(path, PUSHOBJ_DIR)) == 0) {
		return 0;
	}

	return rc;
}

static void free_projdir(struct projdir* pd)
{
	free(pd->basedir);

	if (pd->pgp)
		free(pd->pgp);

	free(pd->userdir);
	free(pd->projdir);
	free(pd);
}

static struct projdir* get_projdir(const char * basedir, const char * sha1_hex, 
		const char * projname)
{
	ssize_t bd_size;
	struct projdir * pd = NULL;
	char * head = NULL;
	char * pgp_file = NULL;
	FILE * fp;

	pd = (struct projdir*)malloc(sizeof(struct projdir));
	bd_size = strlen(basedir) + 1; 

	pd->basedir = (char*)malloc(bd_size);
	memcpy(pd->basedir, basedir, bd_size);

	// convert given sha1_hex, to binary sha1
	get_sha1_hex(sha1_hex, pd->pgp_sha1);

	// ensure dir existence
	pd->userdir = (char*)malloc(strlen(basedir) + 1 + strlen(PUSHOBJ_DIR) + 1
								+ 40 + 1);
	sprintf(pd->userdir, "%s/%s/%s", basedir, PUSHOBJ_DIR, sha1_hex);
	if (access(pd->userdir, W_OK|R_OK|X_OK) != 0)
		die("Unknown user/pgp key, please initialize user first\n");

	pd->projdir = (char*)malloc(strlen(pd->userdir) + strlen(projname) + 1);
	sprintf(pd->projdir, "%s/%s", pd->userdir, projname);
	safe_create_dir(pd->projdir);

	// attempt to get latest pushobj, if exists, if not, create empty file
	memset(pd->head, 0, 41);
	head = (char*)malloc(strlen(pd->projdir) + 1 + 4 + 1);
	sprintf(head, "%s/HEAD", pd->projdir);

	if (access(head, F_OK) == 0) {
		// file exists, open up for reading
		fp = fopen(head, "r");

		if (!fp) {
			perror("Error while looking up head revision\n");
			die()
		}

		if (fread(pd->head, 40, 1, fp) != 1)
			die("error while reading head revision");
		pd->head[40] = '\0';

		fclose(fp);
	} else {
		// HEAD file does not exist, create a new one, also set to 0

		memset(pd->head, '0', 40);
		pd->head[40] = '\0';

		fp = fopen(head, "w");
		fprintf(fp, "%s\n", pd->head);
		fclose(fp);
	}

	// get the PGP stuff
	pgp_file = (char *)malloc(strlen(pd->userdir) + 1 + 3);
	sprintf(pgp_file, "%s/PGP", pd->userdir);
	fp = fopen(pgp_file, "r");
	if (!fp)
		die("error while retrieving PGP info");

	fseek(fp, 0, SEEK_END);
	pd->pgp_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pd->pgp = (unsigned char*)malloc(pd->pgp_len);

	if (fread(pd->pgp, pd->pgp_len, 1, fp) != 1)
		die("error while retrieving PGP info");

	fclose(fp);
	free(pgp_file);

	return pd;
}

/**
 * Update the project head file, and the projdir struct's head
 */
static void update_proj_head(struct projdir * pd, const char * sha1)
{
	FILE * head_fp;
	char * head_path = NULL;

	head_path = (char*)malloc(strlen(pd->projdir) + 1 + 4 + 1);
	sprintf(head_path, "%s/HEAD", pd->projdir);

	head_fp = fopen(head_path, "w");
	fprintf(head_fp, "%s\n", sha1);
	fclose(head_fp);
	
	strcpy(pd->head, sha1);
	free(head_path);
}

/**
 * Given projdir and strbuf containing the pushobject, update with new
 * pushobject and update head file as well as projdir struct.
 * TODO verify pushobj with PGP key
 */
static void append_pushobj(struct projdir * pd, struct strbuf * pobj, 
							struct strbuf *sig)
{
	unsigned char sha1[20];
	char sha1_hex[41];
	FILE * pobj_fp;
	char * file_path;
	git_SHA_CTX c;

	git_SHA1_Init(&c);
	git_SHA1_Update(&c, pobj->buf, pobj->len);
	git_SHA1_Final(sha1, &c);

	file_path = (char*)malloc(strlen(pd->projdir) + 40 + 1);
	strcpy(sha1_hex, sha1_to_hex(sha1));
	sprintf(file_path, "%s/%s", pd->projdir, sha1_hex);

	if (access(file_path, F_OK) == 0) {
		die("Push object alread exists");
	}

	pobj_fp = fopen(file_path, "w");
	fprintf(pobj_fp, "%s", pobj->buf);
	fprintf(pobj_fp, "%s", sig->buf);
	fprintf(pobj_fp, "%s PREV\n", pd->head);
	fclose(pobj_fp);

	update_proj_head(pd, sha1_hex);
	free(file_path);
}

int gidit_update_pl(FILE *fp, const char * base_dir, unsigned int flags)
{
	struct projdir * pd;
	char pgp_sha1[41];
	int ch = 0;
	struct strbuf proj_name = STRBUF_INIT;
	struct strbuf buf = STRBUF_INIT;
	struct strbuf pobj = STRBUF_INIT;

	if (fread(pgp_sha1, 40, 1, fp) != 1)
		die("pgpkey error: bad pushobject format");
	
	pgp_sha1[40] = '\0';

	// next line is the project name
	if (strbuf_getline(&proj_name, fp, '\n') == EOF)
		die("No projname: bad pushobject format");

	pd = get_projdir(base_dir, pgp_sha1, proj_name.buf);

	while (strbuf_getline(&buf, fp, '\n') != EOF) {
		if (strncmp(buf.buf, PGP_SIGNATURE, strlen(PGP_SIGNATURE)) == 0) {
			strbuf_addstr(&buf, "\n");
			break;
		}
		strbuf_addstr(&pobj, buf.buf);
		strbuf_addstr(&pobj, "\n");
	}

	// rest of the stuff is sig stuff
	while ((ch = fgetc(fp)) != EOF) {
		strbuf_grow(&buf, 1);
		buf.buf[buf.len++] = ch;
		buf.buf[buf.len] = '\0';
	}

	append_pushobj(pd, &pobj, &buf);

	free_projdir(pd);
	strbuf_release(&proj_name);
	strbuf_release(&pobj);
	strbuf_release(&buf);

	fclose(fp);

	return 0;
}

int gidit_user_init(FILE *fp, const char * base_dir, unsigned int flags)
{
	int pgp_len;
	FILE * pgp_fp;
	char * userdir = NULL;
	char * pgp_file = NULL;
	char pgp_len_raw[5];
	unsigned char sha1[20];
	unsigned char *pgp_key = NULL;
	git_SHA_CTX c;

	if (fread(pgp_len_raw, 4, 1, fp) != 1) {
		return error("Protocol error, could not read pgp_len");
	}

	pgp_len = strtol(pgp_len_raw, (char**)NULL, 16);

	pgp_key = (unsigned char*)malloc(pgp_len);

	if (fread(pgp_key, pgp_len, 1, fp) != 1) {
		return error("Error while reading pgg_key");
	}

	// hash the pgp key
	git_SHA1_Init(&c);
	git_SHA1_Update(&c, pgp_key, pgp_len);
	git_SHA1_Final(sha1, &c);

	userdir = (char*)malloc(strlen(base_dir) + 1 + strlen(PUSHOBJ_DIR) + 1 + 
							40 + 1);
	sprintf(userdir, "%s/%s/%s", base_dir, PUSHOBJ_DIR, sha1_to_hex(sha1));

	// make sure userdir doesn't exist already
	if (access(userdir, F_OK) == 0) {
		return error("User already exists");
	}

	safe_create_dir(userdir);

	// save the PGP key in there
	pgp_file = (char*)malloc(strlen(userdir) + 1 + 3);
	sprintf(pgp_file, "%s/PGP", userdir);

	pgp_fp = fopen(pgp_file, "w");
	if (!pgp_fp) {
		return error("Error while saving PGP key");
	}

	fwrite(pgp_key, pgp_len, 1, pgp_fp);
	fclose(pgp_fp);

	free(userdir);
	free(pgp_key);
	free(pgp_file);

	return 0;
}
