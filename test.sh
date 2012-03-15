#! /bin/bash

set -eu

rm -fr test

mkdir -p test/var/run
mkdir -p test/var/log
mkdir -p test/tmp1

./aftpd/aftpd -t -d -f test.config -p 8888 &
pid=$!
trap "kill -HUP $pid" 0

echo PID=$pid

sleep 2

curl="curl --user layer:xxx"
url="ftp://quadra.franz.com:8888/"

########################### test 1: copy to

files=`echo /fi/import/unix/*.gz`
for file in $files; do
    $curl -T $file $url/acl/layer/fi-rpm-build/aftpd.i386/test/tmp1/
done
for file in test/tmp1/*.gz; do
    echo Checking $file...
    if ! cmp -s $file /fi/import/unix/$(basename $file); then
	echo ERROR: bad: test/tmp/$(basename $file)
	exit 1
    fi
done
ls="/bin/ls -1"
if test $($ls $files | wc -l) != $($ls test/tmp1/*.gz | wc -l); then
    echo ERROR: counts are off from /fi/import/unix and test/tmp1/
    exit 1
fi

########################### test 2: copy from

mkdir test/tmp2

files="$(echo $PWD/test/tmp1/*.gz)"
for file in $files; do
    $curl -o test/tmp2/$(basename $file) $url$file
done
for file in test/tmp2/*.gz; do
    echo Checking $file...
    if ! cmp -s $file test/tmp2/$(basename $file); then
	echo ERROR: bad: test/tmp2/$(basename $file)
	exit 1
    fi
done
if test $($ls $files | wc -l) != $($ls test/tmp2/*.gz | wc -l); then
    echo ERROR: counts are off from test/tmp1/ and test/tmp2/
    exit 1
fi

###########################

echo TESTS COMPLETED SUCCESSFULLY

set -x
rm -fr test
