#ifndef GIDIT_H
#define GIDIT_H

#define PUSHOBJ_DIR "pushobjects"
#define BUNDLES_DIR "bundles"

#define INCLUDE_TAGS 0x0001

/**
 * Generate a pushobj, which is a list of all refs including HEAD, and
 * excluding stashes and remotes
 */
int gen_pushobj(FILE *fp, char * signingkey, int sign, unsigned int flags);

int gidit_init(const char *path);

/**
 * Read pushobj from fp and save, will need to take
 */
int update_pl(FILE *fp, const char * base_dir, unsigned int flags);

#endif		// GIDIT_H
