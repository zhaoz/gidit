#!/bin/sh
#
# Copyright (c) 2009 Ziling Zhao
#

test_description='git gidit-daemon

Tests for daemon operations with gidit.'

. ./test-lib.sh

export GIDIT_DIR="$TEST_DIRECTORY/gidit_test_dir"
export PROJ_NAME="test"

test -e $GIDIT_DIR && rm -r $GIDIT_DIR

# some commits to start it off
echo "stuff" > tmp
git add tmp
git commit -q -m "added tmp"

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

export PID_FILE=/tmp/gidit_daemon.pid

export PGP_LEN=`printf "%04x" \`gpg --export | wc -c\``
export PGP_SHA1=`gpg --export | sha1sum | head -c 40`

test_expect_success 'start daemon should succeed' '
	git gidit-daemon --pid-file=$PID_FILE --base-path=$GIDIT_DIR &
	sleep 1 && 
	test -e $PID_FILE && 
	test -e $GIDIT_DIR &&
	test -e $GIDIT_DIR/pushobjects &&
	test -e $GIDIT_DIR/bundles
'

test_expect_success 'generate pushobject should succeed' '
	git gidit --pushobj -s > pobj1
'

test_expect_failure 'forced gidit push should work' '
	git gidit --push -f -p hello &&
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/PGP  && 
	test -e $GIDIT_DIR/pushobjects/$PGP_SHA1/$PROJ_NAME 
'


kill `cat $PID_FILE`

# clean up
rm -rf $GIDIT_DIR

test_done


