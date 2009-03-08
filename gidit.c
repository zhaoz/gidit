/*
 * "git gidit"
 */
#include "cache.h"
#include "refs.h"
#include "run-command.h"
#include "builtin.h"
#include "string-list.h"
#include "remote.h"
#include "strbuf.h"
#include "transport.h"
#include "pgp.h"
#include "gidit.h"

#define END_SHA1 "0000000000000000000000000000000000000000"

struct projdir {
	char * basepath;
	int pgp_len;
	unsigned char * pgp;
	unsigned char pgp_sha1[20];
	char * userdir;
	char * projdir;
	char * projname;
	char head[41];
};

struct pushobj {
	int lines;
	char ** refs;
	char * signature;
	char prev[41];
};

#define PO_INIT { 0, NULL, NULL, "\0" }

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

/**
 * Success if directory does not exist yet and was able to create, or 
 * already exists and is writable
 */
static int safe_create_dir(const char *dir)
{
	int rc = 0;
	if (mkdir(dir, 0777) < 0) {
		if (errno != EEXIST) {
			perror(dir);
			rc = error("Error while making directory: %s", dir);
		} else if (access(dir, W_OK)) {
			rc = error("Unable to write to directory: %s", dir);
		}
	}

	return rc;
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
	if (pd->basepath)
		free(pd->basepath);

	if (pd->pgp)
		free(pd->pgp);

	if (pd->userdir)
		free(pd->userdir);

	if (pd->projdir)
		free(pd->projdir);

	if (pd->projname)
		free(pd->projname);

	free(pd);
}

/**
 * Read in projdir data, create projdir if it doesn't exist
 */
static int init_projdir(struct projdir* pd)
{
	int len = 0;
	char * path = NULL;
	FILE * fp;

	if (access(pd->userdir, R_OK|W_OK))
		return error("User does not exist");
	
	if (safe_create_dir(pd->projdir))
		return -1;

	// first get the pgp stuff
	path = (char *)malloc(strlen(pd->userdir) + 1 + 3);
	sprintf(path, "%s/PGP", pd->userdir);

	fp = fopen(path, "r");

	free(path);

	if (!fp)
		return error("error while opening pgp file for reading");

	fseek(fp, 0, SEEK_END);
	pd->pgp_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	pd->pgp = (unsigned char*)malloc(pd->pgp_len);
	len = fread(pd->pgp, pd->pgp_len, 1, fp);
	fclose(fp);

	if (len != 1)
		return error("error while retrieving PGP info");

	if (access(pd->userdir, W_OK|R_OK|X_OK) != 0)
		return error("Unknown user/pgp key, please initialize user first\n");

	path = (char*)malloc(strlen(pd->projdir) + 1 + 4 + 1);
	sprintf(path, "%s/HEAD", pd->projdir);

	if (access(path, F_OK) == 0) {
		fp = fopen(path, "r");

		if (!fp) 
			die("Error while looking up head revision");

		len = fread(pd->head, 40, 1, fp);
		pd->head[40] = '\0';
	} else {
		fp = fopen(path, "w");

		if (!fp) 
			die("Error while looking up head revision");

		memset(pd->head, '0', 40);
		pd->head[40] = '\0';
		fprintf(fp, "%s\n", pd->head);
	}
	free(path);
	fclose(fp);

	return 0;
}

/**
 * Fill out projdir hash
 */
static struct projdir* new_projdir(const char * basepath, const char * sha1_hex, 
		const char * projname)
{
	ssize_t bd_size;
	struct projdir * pd = NULL;

	pd = (struct projdir*)malloc(sizeof(struct projdir));
	bd_size = strlen(basepath) + 1; 

	// Set basepath
	pd->basepath = (char*)malloc(bd_size);
	memcpy(pd->basepath, basepath, bd_size);

	// convert given sha1_hex, to binary sha1
	get_sha1_hex(sha1_hex, pd->pgp_sha1);

	// set the users dir (sha1)
	pd->userdir = (char*)malloc(strlen(basepath) + 1 + strlen(PUSHOBJ_DIR) + 1
								+ 40 + 1);
	sprintf(pd->userdir, "%s/%s/%s", basepath, PUSHOBJ_DIR, sha1_hex);

	// set the project directory inside userdir
	pd->projdir = (char*)malloc(strlen(pd->userdir) + strlen(projname) + 1);
	sprintf(pd->projdir, "%s/%s", pd->userdir, projname);

	pd->projname = (char*)malloc(strlen(projname) + 1);
	strcpy(pd->projname, projname);

	// attempt to get latest pushobj, if exists, if not, create empty file
	if (init_projdir(pd)) {
		free_projdir(pd);
		return NULL;
	}

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
static int append_pushobj(struct projdir * pd, struct strbuf * pobj, 
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

	if (access(file_path, F_OK) == 0)
		return error("Push object alread exists");

	pobj_fp = fopen(file_path, "w");
	fprintf(pobj_fp, "%s", pobj->buf);
	fprintf(pobj_fp, "%s", sig->buf);
	fprintf(pobj_fp, "%s PREV\n", pd->head);
	fclose(pobj_fp);

	update_proj_head(pd, sha1_hex);
	free(file_path);
	return 0;
}

int gidit_update_pl(FILE *fp, const char * basepath, unsigned int flags)
{
	struct projdir * pd;
	char pgp_sha1[41];
	int ch = 0, rc = 0;
	struct strbuf proj_name = STRBUF_INIT;
	struct strbuf buf = STRBUF_INIT;
	struct strbuf pobj = STRBUF_INIT;

	if (fread(pgp_sha1, 40, 1, fp) != 1)
		return error("pgpkey error: bad pushobject format");
	
	pgp_sha1[40] = '\0';

	// next line is the project name
	if (strbuf_getline(&proj_name, fp, '\n') == EOF)
		return error("No projname: bad pushobject format");

	pd = new_projdir(basepath, pgp_sha1, proj_name.buf);

	if (!pd)
		exit(1);

	while (strbuf_getline(&buf, fp, '\n') != EOF) {
		if (strncmp(buf.buf, PGP_SIGNATURE, strlen(PGP_SIGNATURE)) == 0) {
			strbuf_addstr(&buf, "\n");
			break;
		}
		strbuf_addstr(&pobj, buf.buf);
		strbuf_addstr(&pobj, "\n");
	}

	if (!buf.len)
		return error("no pushobject given");

	// rest of the stuff is sig stuff
	while ((ch = fgetc(fp)) != EOF) {
		strbuf_grow(&buf, 1);
		buf.buf[buf.len++] = ch;
		buf.buf[buf.len] = '\0';
	}

	if (!(rc = append_pushobj(pd, &pobj, &buf))) {
		return rc;
	}

	free_projdir(pd);
	strbuf_release(&proj_name);
	strbuf_release(&pobj);
	strbuf_release(&buf);

	fclose(fp);

	return rc;
}

/**
 * Initialize user directories, takes PGP
 */
int gidit_proj_init(FILE *fp, const char * basepath, unsigned int flags)
{
	FILE * pgp_fp;
	struct strbuf pgp_key = STRBUF_INIT;
	struct strbuf proj_name = STRBUF_INIT;
	unsigned char sha1[20];
	char pgp_sha1[41];
	git_SHA_CTX c;

	strbuf_getline(&proj_name, fp, '\n');

	if (proj_name.len == 0) {
		strbuf_release(&pgp_key);
		strbuf_release(&proj_name);
		return error("Error while reading project name\n");
	}

	strbuf_getline(&pgp_key, fp, EOF);

	if (pgp_key.len == 0) {
		strbuf_release(&pgp_key);
		strbuf_release(&proj_name);
		return error("Error while reading pgp_key");
	}

	// hash the pgp key
	git_SHA1_Init(&c);
	git_SHA1_Update(&c, pgp_key.buf, pgp_key.len);
	git_SHA1_Final(sha1, &c);


	// change dir to pushobjects dir
	if (chdir(basepath) || chdir(PUSHOBJ_DIR)) {
		return error("Error going to pushobjects directory\n");
	}

	sprintf(pgp_sha1, "%s", sha1_to_hex(sha1));

	if (safe_create_dir(pgp_sha1))
		exit(1);

	chdir(pgp_sha1);

	// now ensure the project directories existence
	if (safe_create_dir(proj_name.buf))
		exit(1);

	// if pgp key file already exists, not need to resave
	if (access("PGP", F_OK)) {
		// save the PGP key in there
		pgp_fp = fopen("PGP", "w");

		if (!pgp_fp)
			die("Error while saving PGP key");

		fwrite(pgp_key.buf, pgp_key.len, 1, pgp_fp);

		fclose(pgp_fp);
	}
	strbuf_release(&pgp_key);
	strbuf_release(&proj_name);

	return 0;
}

static void pobj_release(struct pushobj *po)
{
	int ii;
	for (ii = 0; ii < po->lines; ii++)
		free(po->refs[ii]);

	if (po->refs)
		free(po->refs);
	if (po->signature)
		free(po->signature);
	
	po->lines = 0;
}

/**
 * Given sha1, look up pushobj and return it
 */
static int sha_to_pobj(struct pushobj *po, const struct projdir *pd, 
						const char * sha1)
{
	FILE * fp;
	int ii;
	char * path = NULL;
	struct string_list list;
	char * cbuf;
	struct strbuf buf = STRBUF_INIT;
	struct strbuf sig = STRBUF_INIT;

	pobj_release(po);

	if (strncmp(sha1, END_SHA1, 40) == 0)
		die("Invalid sha1");

	memset(&list, 0, sizeof(struct string_list));

	path = malloc(strlen(pd->projdir) + 1 + 40 + 1);
	sprintf(path, "%s/%s", pd->projdir, sha1);

	fp = fopen(path, "r");
	if (!fp)
		return error("Could not open pushobj");

	while (strbuf_getline(&buf, fp, '\n') != EOF) {
		if (strncmp(buf.buf, PGP_SIGNATURE, strlen(PGP_SIGNATURE)) == 0)
			break;
		cbuf = (char*)malloc(buf.len);
		strcpy(cbuf, buf.buf);
		string_list_append(cbuf, &list);
	}

	po->lines = list.nr;
	po->refs = (char**)malloc(sizeof(char*) * list.nr);

	for (ii = 0; ii < list.nr; ii++) {
		po->refs[ii] = (char*)malloc(strlen(list.items[ii].string) + 1);
		strcpy(po->refs[ii], list.items[ii].string);
	}

	// rest of the stuff is signature
	strbuf_add(&sig, buf.buf, buf.len);
	strbuf_addstr(&sig, "\n");
	while (strbuf_getline(&buf, fp, '\n') != EOF) {
		strbuf_add(&sig, buf.buf, buf.len);
		strbuf_addstr(&sig, "\n");
		if (strncmp(buf.buf, END_PGP_SIGNATURE, strlen(END_PGP_SIGNATURE)) == 0)
			break;
	}
	po->signature = (char*)malloc(sig.len);
	strcpy(po->signature, sig.buf);

	free(path);
	strbuf_release(&buf);
	strbuf_release(&sig);
	string_list_clear(&list, 0);

	// now the rest of the stuff is the prev pointer
	if (strbuf_getline(&buf, fp, '\n') == EOF) 
		return error("Could not get prev pointer");

	strncpy(po->prev, buf.buf, 40);
	po->prev[40] = '\0';

	strbuf_release(&buf);

	return 0;
}

static void print_pobj(struct pushobj *po)
{
	int ii;
	for (ii = 0; ii < po->lines; ii++)
		printf("%s\n", po->refs[ii]);
	printf("%s", po->signature);
}

int gidit_po_list(FILE *fp, const char * basepath, unsigned int flags)
{
	struct projdir * pd;
	char pgp_sha1[41];
	struct strbuf proj_name = STRBUF_INIT;
	struct pushobj po = PO_INIT;
	int rc = 0;

	if (fread(pgp_sha1, 40, 1, fp) != 1)
		return error("pgpkey error: bad pushobject format");
	pgp_sha1[40] = '\0';
	
	// next line is the project name
	if (strbuf_getline(&proj_name, fp, '\n') == EOF)
		return error("No projname: bad pushobject format");

	fclose(fp);

	pd = new_projdir(basepath, pgp_sha1, proj_name.buf);
	if (!pd)
		exit(1);

	strbuf_release(&proj_name);

	// grab pushobjects and dump them out
	// start with the head pushobj
	if ((rc = sha_to_pobj(&po, pd, pd->head)) != 0)
		die("Failed pushobjlist generation");
	
	print_pobj(&po);

	while (strncmp(po.prev, END_SHA1, 40) != 0 &&
			(rc = sha_to_pobj(&po, pd, po.prev)) == 0) {
		print_pobj(&po);
	}

	if (rc)
		die("Error during pushobjlist generation");

	pobj_release(&po);
	free_projdir(pd);

	return rc;
}
