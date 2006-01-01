# This software is Copyright (c) Franz Inc., 2001-2002.
# Franz Inc. grants you the rights to distribute
# and use this software as governed by the terms
# of the Lisp Lesser GNU Public License
# (http://opensource.franz.com/preamble.html),
# known as the LLGPL.
#
# $Id: makefile,v 1.25 2006/01/01 14:57:38 dancy Exp $
#
# This makefile requires GNU make.

platform = $(shell uname -s)

preferred_lisp=/fi/cl/8.0/bin/mlisp
alt_lisp0=/usr/local/acl80/mlisp
alt_lisp1=/storage1/acl80/mlisp

mlisp:=$(shell if test -x $(preferred_lisp); then \
		echo $(preferred_lisp); \
	     elif test -x $(alt_lisp0); then \
		echo $(alt_lisp0); \
	     elif test -x $(alt_lisp1); then \
		echo $(alt_lisp1); \
	     else \
		echo mlisp; \
	     fi)

INSTALLDIR=/usr/local/sbin

version = $(shell grep defvar..ftpd-version ftpd.cl | sed -e 's,.*"\([0-9.]*\)".*,\1,')
platform = $(shell uname -s)

SOURCE_FILES = BUGS ChangeLog readme.txt binary-license.txt \
	config.cl ftpd.cl ipaddr.cl makefile \
	rfc0959.txt S99aftpd aftpd.init rc.aftpd.sh

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
	cp -pr aftpd \
		makefile \
		S99aftpd \
		aftpd.init \
		rc.aftpd.sh \
		config.cl \
		readme.txt \
	        binary-license.txt \
	        aftpd-$(version)

linux solaris freebsd: clean default pre-dist
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
SUSE = $(shell if grep -qs SuSE /etc/issue; then echo yes; else echo no; fi)
install: install-common
ifeq ($(SUSE),yes)
	cp -p aftpd.init.suse90 /etc/init.d/aftpd
	/sbin/chkconfig --set aftpd on
else
	cp -p aftpd.init /etc/init.d/aftpd
	/sbin/chkconfig aftpd reset
endif
endif

ifeq ($(platform),SunOS)
install: install-common
	cp -p S99aftpd /etc/rc2.d
endif

ifeq ($(platform),FreeBSD)
install: install-common
	cp -p rc.aftpd.sh /usr/local/etc/rc.d/rc.aftpd.sh
endif

FORCE:
