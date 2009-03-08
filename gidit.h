#ifndef GIDIT_H
#define GIDIT_H

#define PUSHOBJ_DIR "pushobjects"
#define BUNDLES_DIR "bundles"

#define INCLUDE_TAGS 0x0001

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
int store_bundle(FILE *fp, const char * basepath, unsigned int flags);

#endif		// GIDIT_H
