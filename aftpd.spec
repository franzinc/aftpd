# $Id: aftpd.spec,v 1.2 2006/08/30 21:23:08 dancy Exp $
Summary: Allegro FTP daemon
Name: aftpd
Version: %{version}
Release: %{release}
License: LLGPL
Group: System Environment/Daemons
Provides: ftpserver
#BuildRequires: allegrocl >= 7.0
Requires: logrotate
Prereq: /sbin/chkconfig, /sbin/service
URL: http://opensource.franz.com/aftpd/
Source0: %{name}-%{version}-src.tgz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
Allegro FTPd is an FTP server for Linux/Solaris written in Allegro
Common Lisp. Because it is written in Common Lisp, one class of
security issues, related to buffer overflows, has been eliminated.

%prep
%setup -q -n %{name}-%{version}-src

%build
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
%makeinstall
# Need to re-make the aftpd symbolic link here so that rpm knows about it.
rm $RPM_BUILD_ROOT/%{_sbindir}/aftpd
ln -s %{_libdir}/aftpd/aftpd $RPM_BUILD_ROOT/%{_sbindir}/aftpd
# 
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
cp aftpd.logrotate $RPM_BUILD_ROOT/etc/logrotate.d/aftpd

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
/etc/init.d/aftpd
%{_sbindir}/aftpd
%{_libdir}/aftpd/*
%config(noreplace) %{_sysconfdir}/aftpd.cl
%config(noreplace) /etc/logrotate.d/aftpd
%doc BUGS ChangeLog readme.txt binary-license.txt

%post
/sbin/chkconfig --add aftpd

%preun
if [ $1 = 0 ]; then
 /sbin/service aftpd stop > /dev/null 2>&1
 /sbin/chkconfig --del aftpd
fi

%postun
if [ "$1" != 0 ]; then
	/sbin/service aftpd condrestart 2>&1 > /dev/null
fi
exit 0

%changelog
* Tue Feb 21 2006 Ahmon Dancy <dancy@dancy> - 1.0.28-1
- Initial build.

