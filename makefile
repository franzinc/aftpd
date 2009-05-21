# This software is Copyright (c) Franz Inc., 2001-2009.
# Franz Inc. grants you the rights to distribute
# and use this software as governed by the terms
# of the Lisp Lesser GNU Public License
# (http://opensource.franz.com/preamble.html),
# known as the LLGPL.
#
# This makefile requires GNU make.

platform = $(shell uname -s)

preferred_lisp=/fi/cl/8.1/bin/mlisp
alt_lisp0=/usr/local/acl81/mlisp
alt_lisp1=/storage1/acl81/mlisp

mlisp:=$(shell if test -x $(preferred_lisp); then \
		echo $(preferred_lisp); \
	     elif test -x $(alt_lisp0); then \
		echo $(alt_lisp0); \
	     elif test -x $(alt_lisp1); then \
		echo $(alt_lisp1); \
	     else \
		echo mlisp; \
	     fi)

prefix ?= /usr/local
sbindir ?= $(prefix)/sbin
sysconfdir ?= /etc
libdir ?= $(prefix)/lib
DOCDIR = $(prefix)/share/doc/aftpd

EXE = $(sbindir)/aftpd
LIB = $(libdir)/aftpd

version = $(shell grep defvar..ftpd-version ftpd.cl | sed -e 's,.*"\([0-9.]*\)".*,\1,')
platform = $(shell uname -s)

DOC_FILES = BUGS ChangeLog readme.txt binary-license.txt
SOURCE_FILES = $(DOC_FILES) \
	config.cl ftpd.cl ipaddr.cl makefile \
	rfc0959.txt S99aftpd aftpd.init rc.aftpd.sh aftpd.logrotate

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
		$(DOC_FILES) \
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
	rm -fr $(LIB) $(EXE)
	mkdir -p $(LIB) $(sbindir)
	cp -p aftpd/* $(LIB)
	ln -s $(LIB)/aftpd $(EXE)
	mkdir -p $(sysconfdir)
	if [ ! -f $(sysconfdir)/aftpd.cl ]; then cp config.cl $(sysconfdir)/aftpd.cl; fi

install-doc: FORCE
	mkdir -p $(DOCDIR)
	cp -p $(DOC_FILES) $(DOCDIR)

ifeq ($(platform),Linux)
SUSE = $(shell if grep -qs SuSE /etc/issue; then echo yes; else echo no; fi)
install: install-common
	mkdir -p $(RPM_BUILD_ROOT)/etc/init.d
ifeq ($(SUSE),yes)
	cp -p aftpd.init.suse90 $(RPM_BUILD_ROOT)/etc/init.d/aftpd
else
	cp -p aftpd.init $(RPM_BUILD_ROOT)/etc/init.d/aftpd
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

release ?= 1

rpm: src
	mkdir -p BUILD RPMS SRPMS
	rpmbuild \
		--define "version $(version)" \
		--define "release $(release)" \
		--define "_sourcedir $(CURDIR)" \
		--define "_topdir $(CURDIR)" \
		--define "_builddir $(CURDIR)/BUILD" \
		--define "_rpmdir $(CURDIR)/RPMS" \
		--define "_srcrpmdir $(CURDIR)/SRPMS" \
		--sign \
		-bb aftpd.spec

FORCE:
