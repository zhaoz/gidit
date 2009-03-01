#ifndef GIDIT_H
#define GIDIT_H

#define PUSHOBJ_DIR "pushobjects"
#define BUNDLES_DIR "bundles"

#define INCLUDE_TAGS 0x0001

int gen_pushobj(FILE *fp, char * signingkey, int sign, unsigned int flags);

int gidit_init(const char *path);

#endif		// GIDIT_H
