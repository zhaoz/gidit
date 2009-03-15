#ifndef GIDIT_H
#define GIDIT_H
#include "chimera.h"

#define PUSHOBJ_DIR "pushobjects"
#define BUNDLES_DIR "bundles"

#define END_SHA1 "0000000000000000000000000000000000000000"

#define INCLUDE_TAGS 0x0001
#define FORCE 0x0002
#define SIGN 0x0004

#define DEFAULT_CHIMERA_PORT 2323
#define DEFAULT_LITSEN_PORT 9898

#define GIDIT_PUSH_MSG 0
#define GIDIT_PUSHF_MSG 1

#define GIDIT_OK 0
#define GIDIT_UNKNOWN_PROJ 1

struct gidit_projdir {
	char * basepath;
	int pgp_len;
	unsigned char * pgp;
	unsigned char pgp_sha1[20];
	char * userdir;
	char * projdir;
	char * projname;
	char head[41];
};

typedef struct chat_m {
	int pid;
	Key source;
	char message[1000];
} chat_message;

struct gidit_pushobj {
	int lines;
	char ** refs;
	char * signature;
	char head[41];
	char prev[41];
};

#define PO_INIT { 0, NULL, NULL, "\0" }

/**
 * Generate a pushobj, which is a list of all refs including HEAD, and
 * excluding stashes and remotes
 */
int gidit_pushobj(FILE *fp, char * signingkey, unsigned int flags);

/**
 * Initialize a gidit directory, that means creating the PUSHOBJ_DIR and 
 * BUNDLES_DIR
 */
int gidit_init(const char *path);

/**
 * Initialize a user's project directory
 */
int gidit_proj_init(FILE *fp, const char * basepath, unsigned int flags);

/**
 * Read pushobj from fp and save, will need to take
 */
int gidit_update_pl(FILE *fp, const char * basepath, unsigned int flags);

/**
 * Generate pushobject list
 */
int gidit_po_list(FILE *fp, const char * basepath, unsigned int flags);

/**
 * save a bundle
 */
int gidit_store_bundle(FILE *fp, const char * basepath, unsigned int flags);

/**
 * get a bundle
 */
int gidit_get_bundle(FILE *fp,  FILE * out, const char * basepath, unsigned int flags);

/**
 * Verify if a pushobject would apply cleanly to repo
 */
int gidit_verify_pushobj(FILE *fp, unsigned int flags);

/**
 * Generate a bundle read from stdin
 */
int gidit_gen_bundle(FILE *fp, unsigned int flags);

int gidit_send_message(char * key, void * message);

/**
 * push stuff out to DHT
 */
int gidit_push(const char * projname, const char *signingkey, unsigned int flags);

/**
 * Function for reading pushobjects
 */
int gidit_read_pushobj(FILE * fp, struct gidit_pushobj *po);

#endif		// GIDIT_H
