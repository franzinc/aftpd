# $Id: makefile,v 1.1 2002/09/16 18:03:16 layer Exp $

default: FORCE
	rm -f build.tmp
	rm -fr aftpd
	echo '(load "config.cl")' >> build.tmp
	echo '(compile-file "ftpd.cl")' >> build.tmp
	echo '(load "ftpd.fasl")' >> build.tmp
	echo '(build)' >> build.tmp
	mlisp-6.2 -batch -q -L build.tmp -kill

clean: FORCE
	rm -fr aftpd *.fasl autoloads.out

FORCE:
