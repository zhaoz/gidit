#!/bin/sh
#
# Copyright (c) 2009 Ziling Zhao
#

test_description='git gidit

Tests for non daemon operations gidit.'

. ./test-lib.sh

GIDIT_DIR=/tmp/gidit_test_dir

test_expect_success 'init gidit directory should succeed' "
	git gidit --init -b $GIDIT_DIR && 
	test -e $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects &&
	test -e $GIDIT_DIR/bundles
"

test_expect_success 'pushobject generation should work, unsigned' '
	git gidit --pushobj &&
	git gidit --pushobj --tags
'

# subsequent tests require gpg; check if it is available
gpg --version >/dev/null
if [ $? -eq 127 ]; then
	echo "gpg not found - skipping tag signing and verification tests"
	test_done
	exit
fi

# key is *same* as from tag tests, comment repeated here:
# key generation info: gpg --homedir t/t7004 --gen-key
# Type DSA and Elgamal, size 2048 bits, no expiration date.
# Name and email: C O Mitter <committer@example.com>
# No password given, to enable non-interactive operation.

cp -R "$TEST_DIRECTORY"/t7004 ./gpghome
chmod 0700 gpghome
GNUPGHOME="$(pwd)/gpghome"
export GNUPGHOME
test_expect_success 'signed pushobject generation should work' '
	git gidit --pushobj -s | grep "BEGIN PGP SIGNATURE"
'

test_done

# clean up
rm -rf $GIDIT_DIR
