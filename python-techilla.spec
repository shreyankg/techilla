%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           python-techilla
Version:        4.4.2
Release:        1%{?dist}
Summary:        Bugzilla XMLRPC client 
License:        GPLv2
Group:          Applications/System
URL:            http://www.redhat.com
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
Requires:       python-pycurl
BuildRequires:  python-devel, python-setuptools

%description
Techilla is an XMLRPC client for Red Hat Bugzilla. It is a replacement for
python-bugzilla module.

%prep
%setup -q

%build
%{__python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README MANIFEST.in 
%{python_sitelib}/bz_xmlrpc/*.py*
%{python_sitelib}/python_techilla*egg-info
%config(noreplace) %{_sysconfdir}/techilla/techilla.conf

%changelog
* Wed Oct 16 2013 Shreyank Gupta <sgupta@redhat.com> - 4.4.2-1
- Moving to curl Transport
- Added pycurl as dependency

* Tue May 21 2013 Shreyank Gupta <sgupta@redhat.com> - 4.4.1-1
- Fix attachment encode issue. Guess Mimetype.

* Mon Apr 22 2013 Shreyank Gupta <sgupta@redhat.com> - 4.4-1
- Initial release.
