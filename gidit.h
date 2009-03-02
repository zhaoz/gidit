#ifndef GIDIT_H
#define GIDIT_H

#define INCLUDE_TAGS 0x0001
#define DEFAULT_CHIMERA_PORT 2323
#define DEFAULT_LITSEN_PORT 9898

int gen_pushobj(FILE *fp, char * signingkey, int sign, unsigned int flags);
int send_message(char * key, void * message);

#endif		// GIDIT_H
