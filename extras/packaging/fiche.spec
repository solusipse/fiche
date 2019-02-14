#
# spec file for package fiche
#
# Copyright (c) 2019 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

Name:           fiche
Version:        0.9.1+git.20181220
Release:        0
Summary:        Command line pastebin for sharing terminal output
License:        MIT
Group:          Productivity/Office/Other
Url:            http://termbin.com
Source:         %{name}-%{version}.tar.xz
Patch0:         0001-Allow-override-of-the-prefix-variable.patch
Patch1:         0002-Add-systemd-unit-and-fiche-user.patch
Requires:       netcat

%description
Fiche it's a command line pastebin service for sharing terminal output,
after setting it up, it becomes quite easy to use as 'command | nc <ip> <port>'
which returns an url that you can easily use in another machine.

%prep
%setup -q
%patch0 -p1
%patch1 -p1

%build
%make_build

%install
%make_install PREFIX=%{_bindir}

%pre
if ! getent passwd fiche > /dev/null; then
  %{_sbindir}/useradd -r -g nogroup -c "Fiche user" \
    -d %{_localstatedir}/lib/fiche fiche 2>/dev/null || :
fi

%post
if [ ! -e %{_localstatedir}/log/fiche ]; then
        install -d 0644 -o %{name} %{_localstatedir}/log/fiche || :
fi


%files
%defattr(-,root,root)
%{_bindir}/%{name}
%license LICENSE
%doc README.md
%{_unitdir}/%{name}@.service

%changelog

