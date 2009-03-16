#ifndef PGP_H
#define PGP_H

#define PGP_SIGNATURE "-----BEGIN PGP SIGNATURE-----"
#define END_PGP_SIGNATURE "-----END PGP SIGNATURE-----"

char signingkey[1000];

void set_signingkey(const char *value);

int set_default_signingkey();

#endif		// PGP_H

