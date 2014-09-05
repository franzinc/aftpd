#! /bin/bash

set -eu

rm -fr test

mkdir -p test/var/run
mkdir -p test/var/log
for sub in test/tmp1 test/tmp2; do
    rm -fr $sub
    mkdir -p $sub
done

testport=8888

./aftpd/aftpd -t -d -f test.config -p $testport &
pid=$!
trap "kill -HUP $pid" 0

echo PID=$pid

sleep 2

me=`id -un`
curl="curl --user $me:password"
pwd=`pwd`
url="ftp://localhost:$testport/$pwd/test/tmp1"

echo url: $url

########################### test 1: copy to

# use source files, etc for testing
files=`find . -maxdepth 1 -type f`

# Upload
for file in $files; do
    $curl --upload-file $file $url/$file
done

# Verify
for file in test/tmp1/*; do
    echo Checking $file...
    if ! cmp -s $file $(basename $file); then
	echo ERROR: bad: $file
	exit 1
    fi
done

########################### test 2: copy from

# Download
for file in test/tmp1/*; do
    $curl -o test/tmp2/$(basename $file) $url/$(basename $file)
done

# Verify
for file in test/tmp2/*; do
    echo Checking $file...
    if ! cmp -s $file test/tmp1/$(basename $file); then
	echo ERROR: bad: $file
	exit 1
    fi
done

###########################

echo TESTS COMPLETED SUCCESSFULLY

set -x
rm -fr test
