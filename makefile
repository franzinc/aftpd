# $Id: makefile,v 1.3 2002/09/16 20:52:39 layer Exp $

default: FORCE
	rm -f build.tmp
	rm -fr aftpd
	echo '(load "config.cl")' >> build.tmp
	echo '(compile-file "ftpd.cl")' >> build.tmp
	echo '(load "ftpd.fasl")' >> build.tmp
	echo '(build)' >> build.tmp
	mlisp-6.2 -batch -q -L build.tmp -kill

version = $(shell grep ftpd-version ftpd.cl | sed -e 's,.*"\([0-9.]*\)".*,\1,')

linux solaris: clean default
	gtar zcf aftpd-$@-$(version).tgz aftpd

SOURCE_FILES = ChangeLog README binary-license.txt config.cl eol.cl \
	ftpd.cl ipaddr.cl makefile passwd.cl posix-lock.cl rfc0959.txt \
	system-constants.c

src: FORCE
	gtar zcf aftpd-$(version)-src.tgz $(SOURCE_FILES)

clean: FORCE
	rm -fr aftpd *.fasl autoloads.out

FORCE: