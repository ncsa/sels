#
# gnupg -- gnu privacy guard
# This is a template.  The dist target uses it to create the real file.
#
%define version 1.4.7
%define name gnupg
Summary: GNU Utility for data encryption and digital signatures
Summary(it): Utility GNU per la sicurezza nelle comunicazioni e nell'archiviazione dei dati.
Summary(cs): GNU n�stroj pro �ifrovanou komunikaci a bezpe�n� ukl�d�n� dat
Summary(fr): Utilitaire GNU de chiffrement et d'authentification des communications et des donn�es
Summary(pl): Narzedzie GNU do szyfrowania i podpisywania danych
Vendor: GNU Privacy Guard Project
Name: %{name}
Version: %{version}
Release: 1
Copyright: GPL
Group: Applications/Cryptography
Group(cs): Aplikace/�ifrov�n�
Group(fr): Applications/Cryptographie
Group(it): Applicazioni/Crittografia
Source: ftp://ftp.gnupg.org/gcrypt/gnupg/%{name}-%{version}.tar.gz
URL: http://www.gnupg.org/
Provides: gpg openpgp
Requires(post,preun): /sbin/install-info
BuildRoot: %{_tmppath}/rpmbuild_%{name}-%{version}

%changelog
* Sun Aug 21 2005 David Shaw <dshaw@jabberwocky.com>
- Distribute gpg-zip.

* Fri Apr 22 2005 David Shaw <dshaw@jabberwocky.com>
- No longer any need to override libexecdir.  The makefiles now
  calculate this correctly internally.

* Wed Feb 16 2005 David Shaw <dshaw@jabberwocky.com>
- Fix problem with storing the gpgkeys helpers in libexec, but calling
  them in libexec/gnupg.

* Wed Jul 30 2003 David Shaw <dshaw@jabberwocky.com>
- Rework much of the spec to use %-macros throughout.
- Fix to work properly with RPM 4.1 (all files in buildroot must be packaged)
- Package and install info files.
- Tweak the English description.
- There is no need to install gpgv and gpgsplit setuid root.

* Sat Nov 30 2002 David Shaw <dshaw@jabberwocky.com>
- Add convert-from-106 script

* Sat Oct 26 2002 David Shaw <dshaw@jabberwocky.com>
- Use new path for keyserver helpers.
- /usr/lib is no longer used for cipher/hash plugins.
- Include gpgv, gpgsplit, and the new gnupg.7 man page.

* Fri Apr 19 2002 David Shaw <dshaw@jabberwocky.com>
- Removed OPTIONS and pubring.asc - no longer used
- Added doc/samplekeys.asc

* Sun Mar 31 2002 David Shaw <dshaw@jabberwocky.com>
- Added the gpgkeys_xxx keyserver helpers.
- Added a * to catch variations on the basic gpg man page (gpg, gpgv).
- Mark options.skel as a config file.
- Do not include the FAQ/faq.html twice (in /doc/ and /share/).

* Wed Sep 06 2000 Fabio Coatti <cova@ferrara.linux.it>
- Added Polish description and summary (Kindly provided by  
  Lukasz Stelmach <stelmacl@ee.pw.edu.pl>)
  
* Thu Jul 13 2000 Fabio Coatti <cova@ferrara.linux.it>
- Added a * to catch all formats for man pages (plain, gz, bz2...)    

* Mon May 01 2000 Fabio Coatti <cova@ferrara.linux.it>
- Some corrections in French description, thanks to Ga�l Qu�ri
  <gqueri@mail.dotcom.fr>; Some corrections to Italian descriptions.

* Tue Apr 25 2000 Fabio Coatti <cova@ferrara.linux.it>
- Removed the no longer needed patch for man page by Keith Owens

* Wed Mar 1 2000 Petr Kri�tof <Petr@Kristof.CZ> 
- Czech descriptions added; some fixes and updates.

* Sat Jan 15 2000 Keith Owens <kaos@ocs.com.au>
- Add missing man page as separate patch instead of updating the tar file.

* Mon Dec 27 1999 Fabio Coatti <cova@ferrara.linux.it> 
- Upgraded for 1.0.1 (added missing gpg.1 man page)

* Sat May 29 1999 Fabio Coatti <cova@ferrara.linux.it>
- Some corrections in French description, thanks to Ga�l Qu�ri <gqueri@mail.dotcom.fr>  

* Mon May 17 1999 Fabio Coatti <cova@felix.unife.it>
- Added French description, provided by 
  Christophe Labouisse <labouiss@cybercable.fr>

* Thu May 06 1999 Fabio Coatti <cova@felix.unife.it> 
- Upgraded for 0.9.6 (removed gpgm)

* Tue Jan 12 1999 Fabio Coatti <cova@felix.unife.it>
- LINGUAS variable is now unset in configure to ensure that all languages will be built. (Thanks to Luca Olivetti <luca@luca.ddns.org>)
 
* Sat Jan 02 1999 Fabio Coatti <cova@felix.unife.it>
- Added pl language file.
- Included g10/pubring.asc in documentation files.

* Sat Dec 19 1998 Fabio Coatti <cova@felix.unife.it>
- Modified the spec file provided by Caskey L. Dickson <caskey-at-technocage.com>
- Now it can be built also by non-root. Installation has to be done as
  root, gpg is suid.
- Added some changes by  Ross Golder <rossigee@bigfoot.com>
- Updates for version 0.4.5 of GnuPG (.mo files)

%description

GnuPG (GNU Privacy Guard) is a GNU utility for encrypting data and
creating digital signatures. GnuPG has advanced key management
capabilities and is compliant with the proposed OpenPGP Internet
standard described in RFC-2440.  Since GnuPG doesn't use any patented
algorithms, it is not compatible with some versions of PGP 2 which use
only the patented IDEA algorithm.  See
http://www.gnupg.org/why-not-idea.html for information on using IDEA
if the patent does not apply to you and you need to be compatible with
these versions of PGP 2.

%description -l it
GnuPG (GNU Privacy Guard) � una utility GNU per la cifratura di dati e
la creazione di firme digitali. Possiede una gestione avanzata delle
chiavi ed � conforme allo standard Internet OpenPGP, descritto nella
RFC 2440. Non utilizzando algoritmi brevettati, non � compatibile con
PGP2 (PGP2.x usa solo IDEA, coperto da brevetto mondiale, ed RSA,
brevettato negli USA con scadenza 20/09/2000). Questi algoritmi sono
utilizzabili da GnuPG tramite moduli esterni.

%description -l fr
GnuPG est un utilitaire GNU destin� � chiffrer des donn�es et � cr�er
des signatures �lectroniques. Il a des capacit�s avanc�es de gestion de
cl�s et il est conforme � la norme propos�e OpenPGP d�crite dans la
RFC2440. Comme GnuPG n'utilise pas d'algorithme brevet�, il n'est
compatible avec aucune version de PGP2 (PGP2.x ne sait utiliser que
l'IDEA brevet� dans le monde entier et RSA, brevet� aux �tats-Unis
jusqu'au 20 septembre 2000). 

%description -l cs
GnuPG je GNU n�stroj pro bezpe�nou komunikaci a ukl�d�n� dat. M��e b�t
pou�it na �ifrov�n� dat a vytv��en� digit�ln�ch podpis�. Obsahuje
funkce pro pokro�ilou spr�vu kl��� a vyhovuje navrhovan�mu OpenPGP
Internet standardu podle RFC2440. Byl vytvo�en jako kompletn�
n�hrada za PGP. Proto�e neobsahuje �ifrovac� algoritmy IDEA nebo RSA,
m��e b�t pou��v�n bez omezen�.
Proto�e GnuPG nepou��v� ��dn� patentovan� algoritmus, nem��e b�t �pln�
kompatibiln� s PGP verze 2. PGP 2.x pou��v� algoritmy IDEA (patentov�no
celosv�tov�) a RSA (patentov�no ve Spojen�ch st�tech do 20. z���
2000). Tyto algoritmy lze zav�st do GnuPG pomoc� extern�ch modul�.

%description -l pl
GnuPG (GNU Privacy Guard) jest nazedziem do szfrowania danych i tworzenia
cyfrowych podpis�w. GnuPG posiada zaawansowane mozliwosci obslugi kluczy
i jest zgodne z OpenPGP, proponowanym standardem internetowym opisanym
w RFC2440. Poniewaz GnuPG nie uzywa zadnych opatentowanych algorytm�w
nie jest wiec zgodne z jaka kolwiek wersja PGP2 (PGP2.x kozysta jedynie
z algorytm�w: IDEA, opatentowanego na calym swiecie, oraz RSA, kt�rego
patent na terenie Stan�w Zjednoczonych wygasa 20 wrzesnia 2000).         

%prep
rm -rf $RPM_BUILD_ROOT

%setup

%build
if test -n "$LINGUAS"; then
 unset LINGUAS
fi    
%configure --program-prefix=%{?_program_prefix:%{_program_prefix}}
make

%install
%makeinstall
%find_lang %{name}
rm %{buildroot}%{_datadir}/%{name}/FAQ
rm %{buildroot}%{_datadir}/%{name}/faq.html
rm -f %{buildroot}%{_infodir}/dir

%files -f %{name}.lang
%defattr (-,root,root)

%doc INSTALL AUTHORS COPYING NEWS README THANKS TODO PROJECTS doc/DETAILS
%doc doc/FAQ doc/faq.html doc/HACKING doc/OpenPGP doc/samplekeys.asc
%doc %attr (0755,root,root) tools/convert-from-106
%config %{_datadir}/%{name}/options.skel
%{_mandir}/man1/*
%{_mandir}/man7/*
%{_infodir}/gnupg1.info*
%attr (4755,root,root) %{_bindir}/gpg
%attr (0755,root,root) %{_bindir}/gpgv
%attr (0755,root,root) %{_bindir}/gpgsplit
%attr (0755,root,root) %{_bindir}/gpg-zip
%attr (0755,root,root) %{_libexecdir}/gnupg/*

%post
/sbin/install-info %{_infodir}/gpg.info %{_infodir}/dir 2>/dev/null || :
/sbin/install-info %{_infodir}/gpgv.info %{_infodir}/dir 2>/dev/null || :

%preun
if [ $1 = 0 ]; then
   /sbin/install-info --delete %{_infodir}/gpg.info \
	%{_infodir}/dir 2>/dev/null || :
   /sbin/install-info --delete %{_infodir}/gpgv.info \
	%{_infodir}/dir 2>/dev/null || :
fi

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}
