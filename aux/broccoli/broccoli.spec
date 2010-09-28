# This spec file creates a single relocatable RPM.
#
%define prefix /usr

Summary: The Bro Client Communications Library
Name: broccoli
Version: 0.9
Release: 1
License: BSD
Group: Development/Libraries
URL: http://www.bro-ids.org
Source: http://www.icir.org/christian/downloads/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Packager: Christian Kreibich <christian@whoop.org> 
Requires: openssl >= 0.9.7a
Requires: openssl-devel >= 0.9.7a
Prefix: %{prefix}

%description
Broccoli enables your applications to speak the Bro communication protocol,
allowing you to compose, send, request, and receive events. You can register
your own event handlers. You can talk to other Broccoli applications or Bro
agents -- Bro agents cannot tell whether they are talking to another
Bro or a Broccoli application. Communications can be SSL-encrypted. Broccoli
turns Bro into a distributed policy-controlled event management system.

%prep
%setup -q
# Needed for snapshot releases.
if [ ! -f configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh --prefix=%prefix
else
  CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%prefix
fi

%build

if [ "$SMP" != "" ]; then
  (make "MAKE=make -k -j $SMP"; exit 0)
  make
else
  make
fi

%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT%{prefix} sysconfdir=$RPM_BUILD_ROOT/etc install

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING ChangeLog NEWS README TODO
%doc %{prefix}/share/gtk-doc/html/broccoli
%{prefix}/lib/lib*.so.*
%{prefix}/lib/lib*a
%{prefix}/include/broccoli.h
%{prefix}/bin/bro*
%{prefix}/share/broccoli/*.bro
/etc/broccoli.conf

%changelog
* Tue Dec  6 2004 Christian Kreibich <christian@whoop.org> 
- Added spec file to tree.
