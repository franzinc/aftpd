# This software is Copyright (c) Franz Inc., 2001-2002.
# Franz Inc. grants you the rights to distribute
# and use this software as governed by the terms
# of the Lisp Lesser GNU Public License
# (http://opensource.franz.com/preamble.html),
# known as the LLGPL.
#
# $Id: makefile,v 1.11 2002/09/17 22:03:01 layer Exp $

INSTALLDIR=/usr/local/sbin

default: FORCE
	rm -f build.tmp
	rm -fr aftpd
	echo '(load "config.cl")' >> build.tmp
	echo '(compile-file "ftpd.cl")' >> build.tmp
	echo '(load "ftpd.fasl")' >> build.tmp
	echo '(build)' >> build.tmp
	mlisp-6.2 -batch -q -L build.tmp -kill
	cp -p makefile aftpd
	cp -p S99aftpd aftpd
	cp -p aftpd.init aftpd
	cp -p readme.txt aftpd
	cp -p binary-license.txt aftpd

version = $(shell grep ftpd-version ftpd.cl | sed -e 's,.*"\([0-9.]*\)".*,\1,')

linux solaris: clean default
	gtar zcf aftpd-$@-$(version).tgz aftpd

SOURCE_FILES = BUGS ChangeLog readme.txt binary-license.txt \
	config.cl eol.cl ftpd.cl ipaddr.cl makefile passwd.cl \
	posix-lock.cl rfc0959.txt \
	system-constants.c S99aftpd aftpd.init

src: FORCE
	mkdir aftpd-$(version)
	cp -p $(SOURCE_FILES) aftpd-$(version)
	gtar zcf aftpd-$(version)-src.tgz aftpd-$(version)
	rm -fr aftpd-$(version)

clean: FORCE
	rm -fr aftpd *.fasl autoloads.out

install-common: FORCE
	rm -fr $(INSTALLDIR)/aftpd
	mkdir -p $(INSTALLDIR)
	cp -pr aftpd $(INSTALLDIR)

install-linux: install-common
	cp -p aftpd.init /etc/init.d/aftpd
	/sbin/chkconfig aftpd reset

install-solaris: install-common
	cp -p S99aftpd /etc/rc2.d

FORCE:
