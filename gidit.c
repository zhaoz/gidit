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
#include "pkt-line.h"
#include "commit.h"
#include "pgp.h"
#include "gidit.h"

#define TEST_DIR "/tmp/gidit"

struct gidit_refs_cb_data {
	struct strbuf *buf;
	struct string_list * list;
	unsigned int flags;
};

static int gen_bundle(struct strbuf *bun, const char * from, const char * to)
{
	struct child_process rls;
	int len;
	const char **argv = xmalloc(6 * sizeof(const char *));
	
	// generate bundle
	memset(&rls, 0, sizeof(rls));
	argv[0] = "bundle";
	argv[1] = "create";
	argv[2] = "-";
	argv[3] = "--branches";
	argv[4] = xmalloc(sizeof(char) * (40 + 40 + 2 + 1));
	argv[5] = NULL;

	sprintf(argv[4], "%s..%s", from, to);

	rls.argv = argv;
	rls.out = -1;
	rls.git_cmd = 1;

	if (start_command(&rls))
		return error("Could not run bundle creation process");
	
	len = strbuf_read(bun, rls.out, 1024);
	close(rls.out);

	if (finish_command(&rls) || !len || len < 0)
		return error("bundle creation failed");

	return 0;
}

/**
 * connect to gidit daemon
 */
static int connect_to_daemon(struct sockaddr_in * daemonAddr, 
							const char * host, unsigned short port)
{
	int sock;

    /* Create a reliable, stream socket using TCP */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        die("socket() failed");

    /* Construct the server address structure */
    memset(daemonAddr, 0, sizeof(host));     /* Zero out structure */
    daemonAddr->sin_family      = AF_INET;             /* Internet address family */
    daemonAddr->sin_addr.s_addr = inet_addr(host);   /* Server IP address */
    daemonAddr->sin_port        = htons(port); /* Server port */

    if (connect(sock, (struct sockaddr *)daemonAddr, sizeof(struct sockaddr_in)) < 0)
        die("connect() failed");

	return sock;
}

static int get_public_key(struct strbuf *buffer, const char * signingkey)
{
	struct child_process gpg;
	const char *args[4];

	memset(&gpg, 0, sizeof(gpg));

	/* When the username signingkey is bad, program could be terminated
	 * because gpg exits without reading and then write gets SIGPIPE. */
	signal(SIGPIPE, SIG_IGN);

	memset(&gpg, 0, sizeof(gpg));
	gpg.argv = args;
	gpg.out = -1;
	args[0] = "gpg";
	args[1] = "--export";
	args[2] = signingkey;
	args[3] = NULL;

	if (start_command(&gpg))
		return error("could not run gpg.");

	while (strbuf_read(buffer, gpg.out, 1024))
		;

	close(gpg.out);

	if (finish_command(&gpg) || !buffer->len)
		return error("gpg failed to return public key");

	return 0;
}


static void pushobj_release(struct gidit_pushobj *po)
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
 * Success if directory does not exist yet and was able to create, or 
 * already exists and is writable
 * return's 0 on success
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


static int read_sha1(FILE *fp, char * buf)
{
	if (fread(buf, 40, 1, fp) != 1)
		return 0;

	buf[40] = '\0';
	return 1;
}

static int enter_bundle_dir(const char * basepath, const char *start_pobj_sha1,
							const char * end_pobj_sha1)
{
	if (chdir(basepath) || chdir(BUNDLES_DIR))
		return 0;

	// ensure creation of start_pobj_sha1
	if (safe_create_dir(start_pobj_sha1) || chdir(start_pobj_sha1))
		return 0;
		 
	if (safe_create_dir(end_pobj_sha1) || chdir(end_pobj_sha1))
		return 0;

	return 1;
}

static int resolve_one_ref(const char *path, const unsigned char *sha1,
			  int flags, void *cb_data)
{
	struct gidit_refs_cb_data *cb = cb_data;
	int is_tag_ref;
	char * cbuf = NULL;

	/* ignore symbolic refs */
	if ((flags & REF_ISSYMREF))
		return 0;

	is_tag_ref = !prefixcmp(path, "refs/tags/");

	// ignore tags and remotes
	if ((is_tag_ref && !(cb->flags & INCLUDE_TAGS)) 
			|| !prefixcmp(path, "refs/remotes/")
			|| !prefixcmp(path, "refs/stash"))
		return 0;
	

	cbuf = (char*)malloc(40 + 1 + strlen(path) + 1);
	sprintf(cbuf, "%s %s", sha1_to_hex(sha1), path);
	string_list_append(cbuf, cb->list);

	strbuf_addstr(cb->buf, cbuf);
	strbuf_addstr(cb->buf, "\n");

	return 0;
}

/**
 * Sign buffer
 */
static int do_sign(struct strbuf * sig, struct strbuf *buffer, 
					const char * signingkey)
{
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
	len = strbuf_read(sig, gpg.out, 1024);
	close(gpg.out);

	if (finish_command(&gpg) || !len || len < 0)
		return error("gpg failed to sign the tag");

	/* Strip CR from the line endings, in case we are on Windows. */
	for (i = j = 0; i < sig->len; i++)
		if (sig->buf[i] != '\r') {
			if (i != j)
				sig->buf[j] = sig->buf[i];
			j++;
		}
	strbuf_setlen(sig, j);

	return 0;
}

void free_projdir(struct gidit_projdir* pd)
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

static int read_ack(int fd)
{
	int status;
	char ch;
	struct strbuf msg = STRBUF_INIT;

	// receive the ack
	if (read(fd, &status, 1) != 1)
		die("error reading ack");

	while (read(fd, &ch, sizeof(char)) == 1) {
		if (ch == '\0')
			break;
		strbuf_grow(&msg, 1);
		msg.buf[msg.len++] = ch;
	}
	if (msg.len) {
		msg.buf[msg.len] = '\0';
		printf("%s\n", msg.buf);
	}

	strbuf_release(&msg);

	return status;
}

static void print_pushobj(FILE * fp, struct gidit_pushobj *po)
{
	int ii;
	fprintf(fp, "%s HEAD\n", po->head);
	for (ii = 0; ii < po->lines; ii++)
		fprintf(fp, "%s\n", po->refs[ii]);
	fprintf(fp, "%s", po->signature);
}

static void strbuf_appendpushobj(struct strbuf * buf, struct gidit_pushobj *po, int sig)
{
	int ii;
	strbuf_addf(buf, "%s HEAD\n", po->head);
	for (ii = 0; ii < po->lines; ii++)
		strbuf_addf(buf, "%s\n", po->refs[ii]);

	if (sig)
		strbuf_addf(buf, "%s", po->signature);
}

/**
 * Read in projdir data, create projdir if it doesn't exist
 */
static int init_projdir(struct gidit_projdir * pd)
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

		if (!read_sha1(fp, pd->head))
			die("Error while reading sha1");
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

static int gen_pushobj(struct gidit_pushobj * po, const char *signingkey, 
						unsigned int flags)
{
	const char *head;
	struct strbuf buf = STRBUF_INIT;
	struct strbuf sig = STRBUF_INIT;
	struct gidit_refs_cb_data cbdata;
	struct string_list list;
	int ii;
	unsigned char head_sha1[20];

	pushobj_release(po);

	memset(&list, 0, sizeof(struct string_list));
	memset(po->head, 0, 40);
	memset(po->prev, 0, 40);

	cbdata.buf = &buf;
	cbdata.flags = flags;
	cbdata.list = &list;

	head = resolve_ref("HEAD", head_sha1, 0, NULL);
	if (!head) {
		strbuf_release(&buf);
		return error("Failed to resolve HEAD as a valid ref.");
	}

	sprintf(po->head, "%s", sha1_to_hex(head_sha1));

	strbuf_add(&buf, sha1_to_hex(head_sha1), 40);
	strbuf_addstr(&buf, " HEAD\n");

	for_each_ref(resolve_one_ref, &cbdata);

	po->lines = list.nr;
	po->refs = (char**)malloc(sizeof(char*) * list.nr);

	for (ii = 0; ii < list.nr; ii++) {
		po->refs[ii] = (char*)malloc(strlen(list.items[ii].string) + 1);
		strcpy(po->refs[ii], list.items[ii].string);
	}

	if (flags & SIGN)
		do_sign(&sig, &buf, signingkey);
	
	po->signature = (char*)malloc(sig.len);
	strncpy(po->signature, sig.buf, sig.len);

	string_list_clear(&list, 0);
	strbuf_release(&buf);
	strbuf_release(&sig);

	return 1;
}


/**
 * Fill out projdir hash
 */
struct gidit_projdir * new_projdir(const char * basepath, const char * sha1_hex, 
		const char * projname)
{
	ssize_t bd_size;
	struct gidit_projdir  * pd = NULL;

	pd = (struct gidit_projdir *)malloc(sizeof(struct gidit_projdir ));
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
static void update_proj_head(struct gidit_projdir * pd, const char * sha1)
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

static void pushobj_to_sha1(unsigned char * sha1, struct gidit_pushobj *po)
{
	struct strbuf buf = STRBUF_INIT;
	git_SHA_CTX c;

	strbuf_appendpushobj(&buf, po, 0);

	git_SHA1_Init(&c);
	git_SHA1_Update(&c, buf.buf, buf.len);
	git_SHA1_Final(sha1, &c);

	strbuf_release(&buf);
}

/**
 * Given projdir and pushobj, update with new
 * pushobject and update head file as well as projdir struct.
 * TODO verify pushobj with PGP key
 */
static int pushobj_add_to_list(struct gidit_projdir *pd, struct gidit_pushobj *po)
{
	unsigned char sha1[20];
	char sha1_hex[41];
	FILE * pobj_fp;
	char * file_path;

	pushobj_to_sha1(sha1, po);

	file_path = (char*)malloc(strlen(pd->projdir) + 40 + 1);
	strcpy(sha1_hex, sha1_to_hex(sha1));
	sprintf(file_path, "%s/%s", pd->projdir, sha1_hex);

	if (access(file_path, F_OK) == 0)
		return error("Push object alread exists");

	pobj_fp = fopen(file_path, "w");
	print_pushobj(pobj_fp, po);
	fprintf(pobj_fp, "%s PREV\n", pd->head);
	fclose(pobj_fp);

	update_proj_head(pd, sha1_hex);
	free(file_path);
	return 0;

}

/**
 * Given sha1, look up pushobj and return it
 */
static int sha1_to_pushobj(struct gidit_pushobj *po, const struct gidit_projdir  *pd, 
						const char * sha1)
{
	FILE * fp;
	char * path = NULL;

	if (strncmp(sha1, END_SHA1, 40) == 0)
		return error("Invalid sha1");

	path = malloc(strlen(pd->projdir) + 1 + 40 + 1);
	sprintf(path, "%s/%s", pd->projdir, sha1);

	fp = fopen(path, "r");
	free(path);
	if (!fp)
		return error("Could not open pushobj");
	
	gidit_read_pushobj(fp, po);

	if (!po->prev)
		return error("No previous pointer in pushobject");

	fclose(fp);

	return 0;
}

static int verify_pushobj(struct gidit_pushobj *po)
{
	int ii;
	const char * prefix = NULL;
	unsigned char sha1[20];
	struct commit * cm = NULL;

	prefix = setup_git_directory();

	get_sha1_hex(po->head, sha1);
	
	// for each ref, verify its existence
	cm = lookup_commit_reference_gently(sha1, 1);
	if (!cm)
		die("Failed verification");
	
	for (ii = 0; ii < po->lines; ++ii) {
		get_sha1_hex(po->refs[ii], sha1);
		if (!lookup_commit_reference_gently(sha1, 1))
			die("Failed verification");
	}

	return 0;
}

int gidit_pushobj(FILE *fp, char * signingkey, unsigned int flags)
{
	struct gidit_pushobj po = PO_INIT;

	if (!gen_pushobj(&po, signingkey, flags))
		die("Error generating pushobject");

	print_pushobj(fp, &po);

	return 0;
}

/**
 * initialize a given directory
 */
int gidit_init(const char *path)
{
	int rc = 0;
	if ((rc = safe_create_dir(path)))
		return rc;

	chdir(path);

	// create these dirs if they don't exist
	if ((rc = safe_create_dir(BUNDLES_DIR)) == 0 && 
			(rc = safe_create_dir(PUSHOBJ_DIR)) == 0) {
		return 0;
	}

	return rc;
}


int gidit_update_pl(FILE *fp, const char * basepath, unsigned int flags)
{
	struct gidit_projdir  * pd;
	char pgp_sha1[41];
	int rc = 0;
	struct strbuf proj_name = STRBUF_INIT;
	struct gidit_pushobj po = PO_INIT;

	if (!read_sha1(fp, pgp_sha1))
		return error("pgpkey error: bad pushobject format");
	
	// next line is the project name
	if (strbuf_getline(&proj_name, fp, '\n') == EOF)
		return error("No projname: bad pushobject format");

	pd = new_projdir(basepath, pgp_sha1, proj_name.buf);

	strbuf_release(&proj_name);

	if (!pd || gidit_read_pushobj(fp, &po))
		exit(1);
	
	rc = pushobj_add_to_list(pd, &po);

	free_projdir(pd);
	pushobj_release(&po);

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
	if (chdir(basepath) || chdir(PUSHOBJ_DIR))
		return error("Error going to pushobjects directory\n");

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

char * gidit_po_list(const char * basepath, const char * pgp_sha1, const char * projname)
{
	char * pobuf = NULL;
	int rc = 0;
	struct strbuf po_list = STRBUF_INIT;
	struct gidit_pushobj po = PO_INIT;
	struct gidit_projdir  * pd;

	pd = new_projdir(basepath, pgp_sha1, projname);
	if (!pd)
		return NULL;
	
	// grab pushobjects and dump them out
	// start with the head pushobj
	if ((rc = sha1_to_pushobj(&po, pd, pd->head)) != 0)
		return NULL;
	
	strbuf_appendpushobj(&po_list, &po, 1);

	while (strncmp(po.prev, END_SHA1, 40) != 0 &&
			(rc = sha1_to_pushobj(&po, pd, po.prev)) == 0)
		strbuf_appendpushobj(&po_list, &po, 1);

	pushobj_release(&po);

	if (rc)
		return NULL;

	free_projdir(pd);

	pobuf = (char*)malloc(po_list.len + 1);
	strcpy(pobuf, po_list.buf);
	pobuf[po_list.len] = '\0';

	strbuf_release(&po_list);

	return pobuf;
}

int gidit_po_list_stream(FILE *fp, const char * basepath, unsigned int flags)
{
	char pgp_sha1[41];
	char * po_list = NULL;
	struct strbuf proj_name = STRBUF_INIT;

	if (!read_sha1(fp, pgp_sha1))
		return error("pgpkey error: bad pushobject format");
	
	// next line is the project name
	if (strbuf_getline(&proj_name, fp, '\n') == EOF)
		return error("No projname: bad pushobject format");

	po_list = gidit_po_list(basepath, pgp_sha1, proj_name.buf);

	strbuf_release(&proj_name);

	if (!po_list)
		die("Could not generate polist");

	printf("%s", po_list);

	free(po_list);

	return 0;
}

int gidit_store_bundle(FILE *fp, const char * basepath, unsigned int flags)
{
	char start_pobj_sha1[41];
	char end_pobj_sha1[41];
	unsigned char bundle_sha1[20];
	struct strbuf bundle = STRBUF_INIT;
	git_SHA_CTX c;
	FILE * out;

	if (!read_sha1(fp, start_pobj_sha1) || !read_sha1(fp, end_pobj_sha1))
		return error("protocol error: could not read sha1");

	if (!enter_bundle_dir(basepath, start_pobj_sha1, end_pobj_sha1))
		return error("Failed to enter gidit pushobj dir");


	// now we need to read in the bundle, and store it in it's own sha1

	strbuf_getline(&bundle, fp, EOF);
	if (bundle.len == 0)
		return error("Protocol error while reading bundle");

	git_SHA1_Init(&c);
	git_SHA1_Update(&c, bundle.buf, bundle.len);
	git_SHA1_Final(bundle_sha1, &c);

	out = fopen(sha1_to_hex(bundle_sha1), "w");

	if (!out)
		die("Error while writing bundle");

	if (fwrite(bundle.buf, bundle.len, 1, out) != 1)
		die("Error while writing to bundle");

	fclose(out);

	strbuf_release(&bundle);

	// create BUNDLE file pointing to sha1
	out = fopen("BUNDLES", "a");

	if (!out)
		die("Error while writing to BUNDLE");

	fprintf(out, "%s\n", sha1_to_hex(bundle_sha1));

	fclose(out);

	return 0;
}

int gidit_get_bundle(FILE *fp, FILE *out, const char *basepath, unsigned int flags)
{
	char start_pobj_sha1[41];
	char end_pobj_sha1[41];
	char bundle_sha1[41];
	int ch;
	FILE * f;

	if (!read_sha1(fp, start_pobj_sha1) || !read_sha1(fp, end_pobj_sha1))
		return error("protocol error: could not read sha1");

	if (!enter_bundle_dir(basepath, start_pobj_sha1, end_pobj_sha1))
		return error("Failed to enter gidit pushobj dir");
	
	// in the directory, attempt to retreive the file name and then dump it out to stdout
	f = fopen("BUNDLES", "r");

	if (!read_sha1(f, bundle_sha1))
		die("Error reading from BUNDLES");
	
	fclose(f);

	f = fopen(bundle_sha1, "r");

	if (!f)
		die("Error getting bundle");
	
	while ((ch = fgetc(f)) != EOF)
		fputc(ch, out);
	

	fclose(f);

	return 0;
}

/**
 * Given a fd, read stuff into pushobj
 * returns 0 on success
 */
int gidit_read_pushobj(FILE * fp, struct gidit_pushobj *po)
{
	int ii;
	int head = 0;
	char * cbuf = NULL;
	struct strbuf buf = STRBUF_INIT;
	struct strbuf sig = STRBUF_INIT;
	struct string_list list;

	pushobj_release(po);

	memset(&list, 0, sizeof(struct string_list));
	memset(po->head, 0, 40);

	while (strbuf_getline(&buf, fp, '\n') != EOF) {
		if (strncmp(buf.buf, PGP_SIGNATURE, strlen(PGP_SIGNATURE)) == 0)
			break;

		// check to see if this is the HEAD ref
		if (strncmp(buf.buf + 41, "HEAD", 4) == 0) {
			strncpy(po->head, buf.buf, 40);
			head = 1;
			continue;
		}

		cbuf = (char*)malloc(buf.len);
		strcpy(cbuf, buf.buf);
		string_list_append(cbuf, &list);
	}

	if (!head)
		die("pushobject did not contain HEAD ref");
	
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

	memset(po->prev, 0, 40);
	
	// now the rest of the stuff is the prev pointer
	if (strbuf_getline(&buf, fp, '\n') != EOF) {
		strncpy(po->prev, buf.buf, 40);
		po->prev[40] = '\0';
	}

	strbuf_release(&buf);
	strbuf_release(&sig);
	string_list_clear(&list, 0);

	return 0;
}

int gidit_verify_pushobj(FILE *fp, unsigned int flags)
{
	int rc = 0;
	struct gidit_pushobj po = PO_INIT;

	gidit_read_pushobj(fp, &po);

	rc = verify_pushobj(&po);

	pushobj_release(&po);

	return rc;
}

int gidit_gen_bundle(FILE *fp, unsigned int flags)
{
	unsigned char head_sha1[20];
	struct gidit_pushobj po = PO_INIT;
	struct strbuf bun = STRBUF_INIT;
	const char *head;
	
	gidit_read_pushobj(fp, &po);

	if (verify_pushobj(&po))
		die("Failed verification");

	// look up current head
	head = resolve_ref("HEAD", head_sha1, 0, NULL);

	if (gen_bundle(&bun, po.head, sha1_to_hex(head_sha1)))
		exit(1);

	if (fwrite(bun.buf, bun.len, 1, stdout) != 1)
		die("Failed to write out bundle");
	
	pushobj_release(&po);
	strbuf_release(&bun);

	return 0;
}

static int parse_url(const char *url, char ** host, int * port, 
						char ** projname)
{
	const char * pt = url + strlen("gidit://");
	const char * pt2 = NULL;
	char * port_c = NULL;
	int size = 0;
	url = pt;

	fprintf(stderr, "url is: %s\n", url);

	if (*pt == '/') {	// use default localhost and 9418
		*host = "localhost";
		*port = 9418;
		url = pt + 1;
	} else {
		pt = strchr(pt, ':');
		pt2 = strchr(pt, '/');

		if (!pt2 || !pt || pt > pt2)	// both these characters should exist
			return 0;

		// there is a : before /, which means we have a port number
		size = pt - url;
		if (size < 1)
			return 0;

		*host = (char*)malloc(size + 1);
		strncpy(*host, url, size);
		(*host)[size] = '\0';

		url = pt + 1;	// url past the /
		size = pt2 - url;
		if (size < 1)
			return 0;

		// rest is port number
		port_c = (char*)malloc(size + 1);
		strncpy(port_c, url, size);
		*port = atoi(port_c);
		free(port_c);

		url = pt2 + 1;
	}

	// parse projectname and pgpkey
	pt = strchr(url, ':');

	if (pt) {
		*projname = (char*)malloc(pt - url + 1);
		strncpy(*projname, url, pt-url);
		(*projname)[pt-url] = '\0';
		pt++;
		
		if (strlen(pt) > sizeof(signingkey))
			return error("signingkey too long");

		strcpy(signingkey, pt);
	} else {
		// signingkey is the default one
		
		*projname = (char*)malloc(strlen(url) + 1);
		strcpy(*projname, url);

		set_default_signingkey();
	}


	return 1;
}

/**
 * Currently refspect and refspec_nr are ignored
 */
int gidit_push(const char * url, int refspec_nr, const char ** refspec, 
				unsigned int flags)
{
	char * host = NULL;
	char * projname = NULL;
	int port;
	int sock;
	struct sockaddr_in addr;
	struct strbuf msg = STRBUF_INIT;
	struct strbuf pgp_key = STRBUF_INIT;
	struct gidit_pushobj po = PO_INIT;
	struct gidit_pushobj po_new = PO_INIT;
	FILE * fd;
	uint32_t len = 0;

	if (!parse_url(url, &host, &port, &projname))
		die("Error parsing url");

	if (get_public_key(&pgp_key, signingkey) != 0)
		exit(1);
	
	sock = connect_to_daemon(&addr, host, port);

	// [message type][pgp len][pgp key][projectname]
	if (flags & TRANSPORT_PUSH_FORCE)
		strbuf_addch(&msg, GIDIT_PUSHF_MSG);
	else
		strbuf_addch(&msg, GIDIT_PUSH_MSG);

	len = htonl(pgp_key.len);
	strbuf_add(&msg, &len, sizeof(uint32_t));
	strbuf_add(&msg, pgp_key.buf, pgp_key.len);

	strbuf_release(&pgp_key);

	strbuf_addstr(&msg, projname);

	// send message to the daemon
	if (write(sock, msg.buf, msg.len + 1) != msg.len+1)
		die("Error communicating with gidit daemon");

	strbuf_release(&msg);

	if (read_ack(sock) != 0)
		die("Push failed");
	
	// now receive the pushobject
	fd = fdopen(sock, "r");
	gidit_read_pushobj(fd, &po);

	// verify the given pushobject
	if (verify_pushobj(&po) != 0)
		die("Failed push object verification");
	
	// create new pushobject and send it off
	if (!gen_pushobj(&po_new, signingkey, flags))
		die("Failed to generate new pushobject");
	
	// generate the bundle, store in msg
	if (gen_bundle(&msg, po.head, po_new.head))
		die("Failed to generate bundle");
	
	// send the bundle and the new pobj off
	print_pushobj(fd, &po_new);

	len = htonl(msg.len);
	if (fwrite(&len, sizeof(uint32_t), 1, fd) != 1 || 
			fwrite(msg.buf, msg.len, 1, fd) != 1)
		die("Failed to send bundle");

	pushobj_release(&po_new);
	strbuf_release(&msg);
	pushobj_release(&po);

	if (read_ack(sock) != 0)
		die("Push failed");

	fclose(fd);

	return 0;
}

/**
 * Update a pushobject list, and verify that our list is a subset of given polist
 */
int gidit_update_pushobj_list(struct gidit_projdir * pd, int num_po, struct gidit_pushobj ** polist)
{
	char found = 0;
	int rc = 0;
	int ii;
	struct gidit_pushobj tmp;

	if (!sha1_to_pushobj(&tmp, pd, pd->head))
		return 1;

	// loop through the polists given and see if they exist
	for (ii = 0; ii < num_po; ++ii) {
		struct gidit_pushobj *po = polist[ii];

		// compare po to tmp and see if they match
		if (strcmp(tmp.head, po->head) == 0) {
			if (!found)
				found = ii;

			// increment to next known pushobject
			rc = sha1_to_pushobj(&tmp, pd, tmp.prev);

			if (ii + 1 != num_po && !rc) {
				// if we aren't on the last polist, and there are no more to walk through, we failed
				pushobj_release(&tmp);
				return 1;
			}
		} else if (found) {
			// we've found a common pushobj, but no longer match, which means diverged chain
			return error("pushobj chain diverged");
		}
	}

	pushobj_release(&tmp);

	if (!found)		// didn't find a similar head something is wrong
		return error("No fastforward found from known latest pushobj");
	
	// we have last known, start updating
	for (ii = found - 1; ii != 0; --ii) {
		struct gidit_pushobj *po = polist[ii];

		if (pushobj_add_to_list(pd, po) != 0)
			return 1;
	}

	return 0;
}

const char * str_to_pushobj(const char *buf, struct gidit_pushobj * po)
{
	struct string_list list;
	char head = 0;
	const char * pt = NULL;
	char * cbuf = NULL;
	int size = 0, ii = 0;
	struct strbuf sig = STRBUF_INIT;

	pushobj_release(po);
	memset(&list, 0, sizeof(struct string_list));
	memset(po->head, 0, 40);

	// get first line
	while ((pt = strchr(buf, '\n')) != NULL) {
		// buf -> pt is one line
		if (strncmp(buf, PGP_SIGNATURE, strlen(PGP_SIGNATURE)) == 0)
			break;

		// check to see if it is the HEAD ref
		if (strncmp(buf + 41, "HEAD", 4) == 0) {
			strncpy(po->head, buf, 40);
			head = 1;
			continue;
		}

		size = pt - buf;
		cbuf = (char*)malloc(size + 1);
		strncpy(cbuf, buf, size);
		cbuf[size] = '\0';
		string_list_append(cbuf, &list);
	}

	if (!head)
		die("pushobject did not contain HEAD ref");

	po->lines = list.nr;
	po->refs = (char**)malloc(sizeof(char*) * list.nr);

	// copy string list over to the pushobject
	for (ii = 0; ii < list.nr; ii++) {
		po->refs[ii] = (char*)malloc(strlen(list.items[ii].string) + 1);
		strcpy(po->refs[ii], list.items[ii].string);
	}

	// rest of the stuff is signature
	// handle sig stuff buf-> pt should hold first line of sig right now
	do {
		strbuf_add(&sig, buf, pt - buf);
		strbuf_addstr(&sig, "\n");
		if (strncmp(buf, END_PGP_SIGNATURE, strlen(END_PGP_SIGNATURE)) == 0)
			break;
	} while ((pt = strchr(buf, '\n')) != NULL);

	po->signature = (char*)malloc(sig.len);
	strcpy(po->signature, sig.buf);

	memset(po->prev, 0, 40);
	
	// now the rest of the stuff is the prev pointer
	/*if (strbuf_getline(&buf, fp, '\n') != EOF) {
		strncpy(po->prev, buf.buf, 40);
		po->prev[40] = '\0';
	} */

	strbuf_release(&sig);
	string_list_clear(&list, 0);

	return pt + 1;
}

int str_to_polist(const char * buf, struct gidit_pushobj ***polist)
{
	int nr = 0;
	int size = 4; // start with 4
	const char * pt = buf;

	*polist = (struct gidit_pushobj **)malloc(sizeof(struct gidit_pushobj *) * size);

	while (1) {
		if (nr == size) {
			size += 4;
			*polist = realloc(*polist, sizeof(struct gidit_pushobj *) * size);
		}

		struct gidit_pushobj * po = (struct gidit_pushobj *)malloc(sizeof(struct gidit_pushobj));

		pt = str_to_pushobj(pt, po);
		(*polist)[nr] = po;

		nr++;
	}


	return nr;
}

