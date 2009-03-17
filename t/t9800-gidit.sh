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

# some commits to start it off
echo "stuff" > tmp
git add tmp
git commit -q -m "added tmp"

test_expect_success 'init gidit directory should succeed' '
	git gidit --init -b $GIDIT_DIR && 
	test -e $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects &&
	test -e $GIDIT_DIR/bundles
'

test_expect_success 'pushobject generation should work, unsigned' '
	git gidit --pushobj -s > pobj1 &&
	git gidit --pushobj --tags
'

test_expect_success 'userdir not inited, should not be able to updatepl' '
	(cat $TEST_DIRECTORY/t9800/pgp_sha1 && echo "$PROJ_NAME" && cat $TEST_DIRECTORY/t9800/pushobj) |
		git gidit --updatepl -b $GIDIT_DIR; 
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

test_expect_success 'User projdir init should work' '
	(echo $PROJ_NAME && gpg --export) | git gidit --proj-init -b $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/PGP  && 
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME 
'

test_expect_success 'pgp key should be the same' '
	gpg --export > pgp_export_raw &&
	cmp pgp_export_raw $GIDIT_DIR/pushobjects/$PGP_SHA1/PGP
'

test_expect_success 'second projdir init should work' '
	(echo test2 && gpg --export) | git gidit --proj-init -b $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/PGP  && 
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/test2 
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

test_expect_success 'Saved PushObject should have HEAD ref' '
	test `cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/\`cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD\` | grep HEAD | wc -l` -eq 1
'

test_expect_success 'polist should work for two objs' '
	(echo -n "$PGP_SHA1$PROJ_NAME") | git gidit --polist -b $GIDIT_DIR > tmpfile &&
	test `cat tmpfile | grep "BEGIN PGP" | wc -l` -eq 2 &&
	test `cat tmpfile | grep "HEAD" | wc -l` -eq 2
'

export POBJ_END_SHA1=`cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD | head -c 40`
export POBJ_START_SHA1=`cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/$POBJ_END_SHA1 | tail -n 1 | head -c 40`
export BUNDLE_SHA1=`cat $TEST_DIRECTORY/t9800/bundle | sha1sum | head -c 40`

test_expect_success 'bundle saving should work' '
	(echo -n "$POBJ_START_SHA1$POBJ_END_SHA1" && cat $TEST_DIRECTORY/t9800/bundle) | git gidit --store-bundle -b $GIDIT_DIR &&
	test -e $GIDIT_DIR/bundles/$POBJ_START_SHA1/$POBJ_END_SHA1/BUNDLES &&
	test -e $GIDIT_DIR/bundles/$POBJ_START_SHA1/$POBJ_END_SHA1/$BUNDLE_SHA1 &&
	test "`cat $GIDIT_DIR/bundles/$POBJ_START_SHA1/$POBJ_END_SHA1/BUNDLES | head -c 40`" = "$BUNDLE_SHA1"
'

test_expect_success 'get bundle should work' '
	(echo -n "$POBJ_START_SHA1$POBJ_END_SHA1") | git gidit --get-bundle -b $GIDIT_DIR > tmp &&
	cmp tmp $TEST_DIRECTORY/t9800/bundle
'

test_expect_success 'verify pushobject should work' '
	cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/`cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD` | git gidit --verify-pobj
'

test_expect_code 128 'verify pushobject with bad ref should fail' '
	(echo "000000000AB1F000000000000000000000000000 fake" && cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/`cat $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME/HEAD`) | git gidit --verify-pobj 
'


test_expect_success 'second pobj creation should work' '
	echo "stuff" > tmp2 &&
	git add tmp2 &&
	git commit -m "added tmp2" &&
	echo "hello" >> tmp &&
	git commit -a -m "another update" &&
	git gidit --pushobj -s > pobj2
'

test_expect_code 1 'second pobj should be different from first' '
	cmp pobj1 pobj2 -s
'

test_expect_success 'bundle gen from pushobjects should succeed' '
	echo "stuff2" >> tmp2 &&
	git commit -a -m "up" &&
	(cat pobj2) | git gidit --create-bundle > bdn1 &&
	git bundle create bdn2 --branches `cat pobj2 | grep HEAD | head -c 40`..`git log -n1 HEAD --pretty=oneline | head -c 40` &&
	cmp bdn1 bdn2
'

# clean up
rm -rf $GIDIT_DIR

test_done

