#ifndef GIDIT_H
#define GIDIT_H
#include "chimera.h"

#define PUSHOBJ_DIR "pushobjects"
#define BUNDLES_DIR "bundles"

#define INCLUDE_TAGS 0x0001
#define DEFAULT_CHIMERA_PORT 2323
#define DEFAULT_LITSEN_PORT 9898

typedef struct chat_m{
	int pid;
	Key source;
	char message[1000];
} chat_message;

int gidit_send_message(char * key, void * message);

/**
 * Generate a pushobj, which is a list of all refs including HEAD, and
 * excluding stashes and remotes
 */
int gidit_pushobj(FILE *fp, char * signingkey, int sign, unsigned int flags);

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

#endif		// GIDIT_H
