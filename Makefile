# This software is Copyright (c) Franz Inc., 2001-2012.
# Franz Inc. grants you the rights to distribute
# and use this software as governed by the terms
# of the Lisp Lesser GNU Public License
# (http://opensource.franz.com/preamble.html),
# known as the LLGPL.

at_franz = $(shell if test -d /fi/cl/8.2/acl; then echo t; else echo nil; fi)

Makefile_local = \
	$(shell if test -f Makefile.local; then echo Makefile.local; fi)

ifneq ($(Makefile_local),)
include $(Makefile_local)
endif

platform ?= $(shell uname -s)
ARCH ?= $(shell uname -i)

ifeq ($(at_franz),t)
LISPROOT ?= /fi/cl/8.2
LISP ?= $(LISPROOT)/bin/$(shell if [ $(ARCH) = x86_64 ]; then echo mlisp-64; else echo mlisp; fi)
endif

LISP ?= mlisp

ROOT ?= /
prefix ?= $(ROOT)/usr
ifeq ($(ARCH),x86_64)
libdir ?= $(prefix)/lib64
else
libdir ?= $(prefix)/lib
endif
sbindir ?= $(prefix)/sbin

version := $(shell grep defvar..ftpd-version ftpd.cl | sed -e 's,.*"\([0-9.]*\)".*,\1,')

ifeq ($(FI_APPS_COMMON),t)
release ?= $(shell . fi-apps-common/rpm-utils.sh && \
	rpm_next_release_number \
	   /net/$(REPOHOST)$(REPOBASE)/$(ARCH)/aftpd-$(version)-*.$(ARCH).rpm)
else
release ?= 1
endif

installer-package := aftpd-$(version)-installer.tar.gz

REDHAT73 := $(shell rpm -q redhat-release-7.3 >/dev/null && echo yes)
SUSE92 := $(shell rpm -q suse-release-9.2 >/dev/null && echo yes)

DOC_FILES = BUGS ChangeLog readme.txt binary-license.txt
SOURCEFILES = $(DOC_FILES) \
	config.cl ftpd.cl ipaddr.cl Makefile \
	rfc0959.txt S99aftpd aftpd.init rc.aftpd.sh aftpd.logrotate

ifeq ($(at_franz),t)
ALL_EXTRA = repo_check
endif

all: $(ALL_EXTRA) clean aftpd/aftpd

ifeq ($(at_franz),t)
repo_check: FORCE
	@if test ! -d fi-apps-common; then \
	    git clone git:/repo/git/fi-apps-common; \
	fi
endif


aftpd/aftpd: FORCE
	rm -f build.tmp
	rm -fr aftpd
	echo '(load "config.cl")' >> build.tmp
	echo '(setq excl::*break-on-warnings* t)' >> build.tmp
	echo '(compile-file "ftpd.cl")' >> build.tmp
	echo '(load "ftpd.fasl")' >> build.tmp
	echo '(build)' >> build.tmp
	$(LISP) -batch -q -L build.tmp -kill

install: FORCE
	mkdir -p $(ROOT)/etc/init.d
	cp -p aftpd.init $(ROOT)/etc/init.d/aftpd
	rm -fr $(libdir)/aftpd.old
	-mv $(libdir)/aftpd $(libdir)/aftpd.old
	cp -r aftpd $(libdir)
	rm -f $(sbindir)/aftpd
	ln -s $(libdir)/aftpd/aftpd $(sbindir)/aftpd
	mkdir -p $(ROOT)/etc
	if [ ! -e $(ROOT)/etc/aftpd.cl ]; then \
	    cp config.cl $(ROOT)/etc/aftpd.cl; \
	fi

clean: FORCE
	rm -fr aftpd *.fasl autoloads.out build.tmp
# generated:
	rm -f aftpd.spec
	rm -fr BUILD BUILDROOT RPMS SRPMS SPECS

tarball: all
	tar zcf aftpd.tar.gz aftpd

dist: tarball
	tar zcf $(installer-package) \
		aftp.tar.gz \
		aftpd.init

src-tarball: FORCE
	rm -fr aftpd-$(version) aftpd-$(version).tar.gz
	mkdir aftpd-$(version)
	cp -p $(SOURCEFILES) aftpd-$(version)
	if test -f Makefile.local; then \
	    cp Makefile.local aftpd-$(version); \
	fi
	tar zcf aftpd-$(version).tar.gz aftpd-$(version)
	rm -fr aftpd-$(version)

%.spec: %.spec.in ftpd.cl
	sed -e "s/__VERSION__/$(version)/" < $< > $@

rpm-setup: FORCE
	mkdir -p BUILD RPMS SRPMS

SIGN ?= --sign

rpm: aftpd.spec src-tarball rpm-setup
	rpmbuild $(SIGN) --define "_sourcedir $(CURDIR)" \
		--define "_topdir $(CURDIR)" \
		--define "_builddir $(CURDIR)/BUILD" \
		--define "_rpmdir $(CURDIR)/RPMS" \
		--define "_srcrpmdir $(CURDIR)/SRPMS" \
		--define "release $(release)" \
		--target $(ARCH) -ba aftpd.spec

REMOVE_PREVIOUS_VERSIONS ?= no
REPOHOST                 ?= fs1
REPOBASE                 ?= /storage1/franz/common

REPODIR=$(REPOBASE)/$(ARCH)

install-repo: FORCE
ifeq ($(REMOVE_PREVIOUS_VERSIONS),yes)
	ssh root@$(REPOHOST) "rm -f $(REPODIR)/aftpd-*"
endif
	scp -p RPMS/$(ARCH)/aftpd-$(version)-*.rpm root@$(REPOHOST):$(REPODIR)
	ssh root@$(REPOHOST) "createrepo -s sha -q --update $(REPODIR)"

test: FORCE
	./test.sh

FORCE:
