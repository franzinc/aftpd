# This software is Copyright (c) Franz Inc., 2001-2002.
# Franz Inc. grants you the rights to distribute
# and use this software as governed by the terms
# of the Lisp Lesser GNU Public License
# (http://opensource.franz.com/preamble.html),
# known as the LLGPL.
#
# $Id: makefile,v 1.14 2002/09/17 22:38:06 layer Exp $

INSTALLDIR=/usr/local/sbin

version = $(shell grep ftpd-version ftpd.cl | sed -e 's,.*"\([0-9.]*\)".*,\1,')

SOURCE_FILES = BUGS ChangeLog readme.txt binary-license.txt \
	config.cl eol.cl ftpd.cl ipaddr.cl makefile passwd.cl \
	posix-lock.cl rfc0959.txt \
	system-constants.c S99aftpd aftpd.init

default: FORCE
	rm -f build.tmp
	rm -fr aftpd
	echo '(load "config.cl")' >> build.tmp
	echo '(compile-file "ftpd.cl")' >> build.tmp
	echo '(load "ftpd.fasl")' >> build.tmp
	echo '(build)' >> build.tmp
	mlisp-6.2 -batch -q -L build.tmp -kill
	rm -fr aftpd-$(version)
	mkdir aftpd-$(version)
	cp -p makefile aftpd-$(version)
	cp -p S99aftpd aftpd-$(version)
	cp -p aftpd.init aftpd-$(version)
	cp -p config.cl aftpd-$(version)
	cp -p readme.txt aftpd-$(version)
	cp -p binary-license.txt aftpd-$(version)
	mv aftpd aftpd-$(version)

linux solaris: clean default
	gtar zcf aftpd-$@-$(version).tgz aftpd-$(version)

src: FORCE
	mkdir aftpd-$(version)-src
	cp -p $(SOURCE_FILES) aftpd-$(version)-src
	gtar zcf aftpd-$(version)-src.tgz aftpd-$(version)-src
	rm -fr aftpd-$(version)-src

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
