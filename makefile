# $Id: makefile,v 1.2 2002/09/16 18:29:02 layer Exp $

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
	mv aftpd/* binaries/$@/aftpd
	gtar zcf aftpd-$@-$(version).tgz -C binaries/$@ aftpd

clean: FORCE
	rm -fr aftpd *.fasl autoloads.out

FORCE:
