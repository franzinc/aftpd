# This software is Copyright (c) Franz Inc., 2001-2002.
# Franz Inc. grants you the rights to distribute
# and use this software as governed by the terms
# of the Lisp Lesser GNU Public License
# (http://opensource.franz.com/preamble.html),
# known as the LLGPL.
#
# $Id: makefile,v 1.21 2004/01/14 20:41:48 dancy Exp $
#
# This makefile requires GNU make.

platform = $(shell uname -s)

ifeq ($(platform),Linux)
mlisp = $(shell if test -x /storage1/acl/mlisp; then \
	           echo /storage1/acl/mlisp; \
                else \
                   echo /fi/cl/6.2/bin/redhat6/mlisp; \
                fi)
else
mlisp = /fi/cl/6.2/bin/solaris/mlisp
endif

INSTALLDIR=/usr/local/sbin

version = $(shell grep defvar..ftpd-version ftpd.cl | sed -e 's,.*"\([0-9.]*\)".*,\1,')
platform = $(shell uname -s)

SOURCE_FILES = BUGS ChangeLog readme.txt binary-license.txt \
	config.cl ftpd.cl ipaddr.cl makefile \
	rfc0959.txt S99aftpd aftpd.init

default: FORCE
	rm -f build.tmp
	rm -fr aftpd
	echo '(load "config.cl")' >> build.tmp
	echo '(setq excl::*break-on-warnings* t)' >> build.tmp
	echo '(compile-file "ftpd.cl")' >> build.tmp
	echo '(load "ftpd.fasl")' >> build.tmp
	echo '(build)' >> build.tmp
	$(mlisp) -batch -q -L build.tmp -kill

pre-dist: FORCE
	rm -fr aftpd-$(version)
	mkdir aftpd-$(version)
	cp -p makefile aftpd-$(version)
	cp -p S99aftpd aftpd-$(version)
	cp -p aftpd.init aftpd-$(version)
	cp -p config.cl aftpd-$(version)
	cp -p readme.txt aftpd-$(version)
	cp -p binary-license.txt aftpd-$(version)
	cp -rp aftpd aftpd-$(version)

linux solaris: clean default pre-dist
	gtar zcf aftpd-$@-$(version).tgz aftpd-$(version)

src: FORCE
	mkdir aftpd-$(version)-src
	cp -p $(SOURCE_FILES) aftpd-$(version)-src
	gtar zcf aftpd-$(version)-src.tgz aftpd-$(version)-src
	rm -fr aftpd-$(version)-src

clean: FORCE
	rm -fr aftpd *.fasl autoloads.out build.tmp

install-common: FORCE
	rm -fr $(INSTALLDIR)/aftpd
	mkdir -p $(INSTALLDIR)
	cp -pr aftpd $(INSTALLDIR)
	cp -p readme.txt $(INSTALLDIR)/aftpd
	cp -p config.cl $(INSTALLDIR)/aftpd
	cp -p binary-license.txt $(INSTALLDIR)/aftpd

ifeq ($(platform),Linux)
install: install-common
	cp -p aftpd.init /etc/init.d/aftpd
	/sbin/chkconfig aftpd reset
endif

ifeq ($(platform),SunOS)
install: install-common
	cp -p S99aftpd /etc/rc2.d
endif

FORCE:
