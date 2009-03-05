#!/bin/sh
#
# Copyright (c) 2009 Ziling Zhao
#

test_description='git gidit

Tests for non daemon operations gidit.'

. ./test-lib.sh

export GIDIT_DIR="$TEST_DIRECTORY/gidit_test_dir"
export PROJ_NAME="test"

test -e $GIDIT_DIR && rm -r $GIDIT_DIR

test_expect_success 'init gidit directory should succeed' '
	git gidit --init -b $GIDIT_DIR && 
	test -e $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects &&
	test -e $GIDIT_DIR/bundles
'

test_expect_success 'pushobject generation should work, unsigned' '
	git gidit --pushobj &&
	git gidit --pushobj --tags
'


test_expect_success 'userdir not inited, should not be able to updatepl' '
	(cat $TEST_DIRECTORY/t9800/pgp_sha1 && echo "$PROJ_NAME" && cat $TEST_DIRECTORY/t9800/pushobj) | git gidit --updatepl -b $GIDIT_DIR; 
	test $? -ne 0
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
	git gidit --pushobj -u committer | grep "BEGIN PGP SIGNATURE"
'

export PGP_LEN=`printf "%04x" \`gpg --export | wc -c\``
export PGP_SHA1=`gpg --export | sha1sum | head -c 40`

test_expect_success 'User dir init should work' '
	(echo -n $PGP_LEN && gpg --export) | git gidit --user-init -b $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/PGP 
'

test_expect_success 'PushObject update should work' '
	(echo -n $PGP_SHA1 && echo $PROJ_NAME && cat $TEST_DIRECTORY/t9800/pushobj) | git gidit --updatepl -b $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/`cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD`
'

test_expect_success 'PushObject update should fail on no pushobj' '
	(echo -n $PGP_SHA1 && echo -n $PROJ_NAME) | git gidit --updatepl -b $GIDIT_DIR;
	test $? -ne 0 &&
	test `ls $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME | wc -l` -eq 2
'

test_expect_success 'polist should work' '
	(echo -n "$PGP_SHA1$PROJ_NAME") | git gidit --polist -b $GIDIT_DIR > tmpfile &&
	test `cat tmpfile | grep "BEGIN PGP" | wc -l` -eq 1
'

# generate another pushobj update
test_expect_success 'Second PushObject update should work' '
	(echo "$PGP_SHA1$PROJ_NAME" && git gidit --pushobj -s) | git gidit --updatepl -b $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/`cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD` && 
	test `ls $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME | wc -l` -eq 3
'

test_expect_success 'polist should work for two objs' '
	(echo -n "$PGP_SHA1$PROJ_NAME") | git gidit --polist -b $GIDIT_DIR > tmpfile &&
	test `cat tmpfile | grep "BEGIN PGP" | wc -l` -eq 2
'

# clean up
rm -rf $GIDIT_DIR

test_done

