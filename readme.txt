Allegro FTPd documentation

Table of Contents:

1. Installation
   A. from source code
   B. using the supplied binaries
2. Configuration
   A. anonymous FTP setup
   B. Firewall considerations
   C. Restricted users
3. Security notes

*******************************************************************************
1. Installation

Allegro FTPd (aFTPd) has been tested on Linux, Solaris, and FreeBSD on
Allegro Common Lisp.  Other platforms supported by Allegro Common Lisp
may work as well but Allegro FTPd has not be tested on them.

You can either build aFTPd from sources or use the binaries built by
Franz Inc.  If you want to build your own, then you must have Allegro
Common Lisp Enterprise Edition, version 7.0 or better.

*******************************************************************************
1A. Installation: from source code

The source code to aFTPd is licensed under the terms of the Lisp
Lesser GNU Public License (http://opensource.franz.com/preamble.html),
known as the LLGPL.  The LLGPL consists of a preamble (see above URL)
and the LGPL.  Where these conflict, the preamble takes precedence.
aFTPd is referenced in the preamble as the "LIBRARY."

Download and unpack the source code.  Then, startup Allegro CL
Enterprise and type, in the directory containing the source code:

	   :ld load.cl
	   (build)

or just type "make" (requires GNU make, which is typically installed
as /usr/local/bin/gmake on FreeBSD).

This will make an `aftpd' directory with the program `aftpd' and
supporting files.  Use this directory in step (1C).

*******************************************************************************
1B. Installation: using the supplied binaries

You may use the supplied binaries if you do not have a copy of Allegro
Common Lisp Enterprise Edition. The Linux binaries will work on x86
Red Hat 7.3 or later, or any glibc 2.2 capable system.  The Solaris
binaries will work on Solaris 5.8 or later.  The FreeBSD binaries will
work on FreeBSD 4.10 or later.  See the file binary-license.txt for
the license terms for use of these binaries.

When extracted the .tgz files will create the `aftpd' from step (1A).
Use this directory in step (1C).

*******************************************************************************
1C. Installation: finishing up

Now that you have an aftpd/ directory (either by building or
extracting a pre-built binary) you can complete the installation
process.  

First, make sure that you have disabled any existing ftp server you
might have configured on your system.  Verify by attempting to make an
ftp connection to localhost.  If you get a connection refused
response, then there is no FTP server running.

The default installation process installs the program in the
/usr/local/sbin/aftpd directory.  If this is not what you want, you
can edit 'makefile' and the appropriate startup script for the
platform:
  Linux:  aftpd.service [systemd]
  Solaris: S99aftpd
  FreeBSD: rc.aftpd.sh

To finish the installation, do:

   # make install

NOTE: you must have GNU make to use the supplied makefile.  On
FreeBSD, GNU make is typically installed as /usr/local/bin/gmake.

This will copy the aftpd directory into /usr/local/sbin and install
the appropriate scripts to make the FTP server start up at boot time.
For Linux, the installation is assumed to be Redhat-like.

To execute the server by hand, run /usr/local/sbin/aftpd/aftpd.
Information on optional command line switches follows.

The FTP server only works properly when run as 'root'.

*******************************************************************************
2. Configuration

Allegro FTPd configuration is determined by the defparameter forms in
config.cl.  Most of the forms have comments which indicate their
proper use.  All of the parameters can be overridden at runtime by the
/etc/aftpd.cl file (or whichever pathname is specified in *configfile*
in ftpd.cl).  /etc/aftpd.cl is loaded when the FTP server is first
started, and every time a new connection is made.  Simply supply setq
forms in /etc/aftpd.cl to override default configuration variables.

Command line options:

-f file		Use alternate config file.
-d		Run in debug mode [doesn't fork]
-p portnum	Use alternate ftp server port

*******************************************************************************
2A. Configuration: anonymous FTP setup

There are two configuration variables related to the anonymous FTP
account.  *anonymous-ftp-names* lists the desired aliases for the
anonymous login account.  The default value of *anonymous-ftp-names*
is ("ftp" "anonymous"), which means that supply the login name 'ftp'
or 'anonymous' during an FTP login session will initiate an anonymous
FTP session.

The second configuration variable is *anonymous-ftp-account*.  This
variable defaults to "ftp" and names the local account under which
operations will be performed during the anonymous FTP session.  Make
sure the account exists in /etc/passwd. 


The home directory for the *anonymous-ftp-account* should be set up
for a chroot environment.  Required files (relative to the chroot'd
home directory)

/dev/null
    Linux:
      mknod null c 1 3; chmod a+w null
    Solaris:
      mknod null c 13 2; chmod a+w null
    FreeBSD:
      mknod null c 2 2; chmod a+w null

Optional:

/welcome.msg
    Displayed after authentication has been completed.

/etc/passwd
/etc/group
    If you want 'ls' to display user/group names instead of id
    numbers.

/bin/tar
/bin/zip
/bin/bzip2
/bin/gzip
/bin/compress
    If you want conversions. Don't forget their shared libraries.

No files/directories should be writeable except for those directories
in which you want to allow anonymous FTP uploads.

*******************************************************************************
2B. Configuration: Firewall considerations

For passive FTP to work, the ports specified by *pasvrange* in
config.cl must be open on the firewall.  Additionally, *ftpport*
should be open.

*******************************************************************************
2C. Configuration: Restricted users

Restricted users:

If you would like to give a user restricted FTP access to files in
their home directory (and below), you can use the *restricted-users*
feature.  

*restricted-users* defaults to the empty list, meaning no regular
users are restricted.  To restrict users, simply set this variable to
the list of those user's login name strings.  For example, to restrict
users joe, bobby, and mike, add the following line to /etc/aftpd.cl:

(setq *restricted-users* '("joe" "bobby" "mike"))

To restrict a single user, you must still use a list like so:

(setq *restricted-users* '("joe"))

This feature is best for FTP-only users, i.e., users that have no
other file access on the system beyond FTP.  If a user has, for
example, shell or NFS access to the system, they could make a symbolic
link in their home directory that will allow them to escape this
restriction.  The FTP protocol implemented in this version of the
Allegro FTPd doesn't allow for the creation of symbolic links, so
FTP-only accounts shouldn't (in the absence of bugs) be able to
escape.  

The usual way of disabling shell access for an account is to change
the user's shell to something like /sbin/nologin or /bin/false.
Again, make sure that you've disabled any other possible filesystem
access methods that may be available to the restricted user.

If you want to allow a restricted user to reach other restricted
subsets of the filesystem, you can make symbolic links in their home
directory which point to other directories.  As long as those
directories and subdirectories don't have symbolic links which point
outside of them, the user will remain confined within them.

The restricted user feature works by keeping careful track of the
user's current working directory.  When a restricted user initially
logs in, their cwd (current working directory) is set to their home
directory (as stated in /etc/passwd).  All pathnames that a user
enters are parsed and converted into absolute pathnames.  When the
pathname parser encounters '..', it strips one component from the tail
of the pathname.  All absolute pathnames must have a prefix that is
equal to the restricted user's directory, otherwise access will be
denied.

The following example illustrates these concepts:

[User's home directory is /home/dancy]
login:  cwd starts at /home/dancy

cd ..:  disallowed because absolute pathname is /home

cd /:  disallowed because absolute pathname is /

cd ../../home/dancy:  allowed because absolute pathname is /home/dancy

cd somedir:  allowed because absolute pathname is /home/dancy/somedir.
[cwd is now /home/dancy/somedir]

cd ..:  allowed because absolute pathname is /home/dancy
[cwd is now /home/dancy]

[Assume that 'dirptr' is a symbolic link to /home/joe]
cd dirptr:  allowed because absolute pathname is /home/dancy/dirptr 
            even though the ultimate destination, as far as the
            operating system is concerned, is /home/joe.
[cwd is now /home/dancy/dirptr]

cd ..:  allowed because absolute pathname is /home/dancy again.

*******************************************************************************
3. Security notes

Since this FTP server is written in Common Lisp, it should be free of
buffer overflows.  None of the used foreign functions populate any
variable-sized buffers so things should be safe on that front as well.
One target of attack may be the conversions.  Bugs in conversion
programs could lead to security compromises.  For example, gzip-1.2.4
may suffer a buffer overflow if its command line is too long (see
http://www.securityfocus.com/advisories/3801 ).  Make sure all of your
conversion programs are up-to-date.  If you're really worried, you can
set *conversions* to 'nil' to disallow all conversions.  If you want
to audit the security of this FTP server, it is recommended that you
examine the make-full-path and glob functions (and their callers and
callees).

*******************************************************************************
4. *pasvipaddrs* example and information.

(setf *pasvipaddrs* 
  '(("192.168.1.0/24" . "192.168.1.99")
    ("192.168.2.0/255.255.255.0" . "192.168.1.98")
    ("127.0.0.1" . "127.0.0.1")
    ("0.0.0.0/0" . "99.44.22.54")))

This is a contrived example of a complicated network.  The first two
entries show two different ways of specifying the network number and
netmask.  Clients connecting from 192.168.1.x will be told to use the
address 192.168.1.99 for their PASV connections.  Clients from
192.168.2.x will be told to use 192.168.1.98.  The single client from
127.0.0.1 (localhost) will be told to use 127.0.0.1.  This is a
reasonable rule to have in all configurations..  The final entry
serves as a default entry.  If the client's IP address doesn't match
any other entry, this entry will be used.  If no default entry is
specified, the FTP server will use the IP address of its side of the
FTP control connection.  Note that this does not affect the IP
interface to which the passive connection is bound.  It only controls
that address that is returned to the client.
