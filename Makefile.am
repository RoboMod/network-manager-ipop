AUTOMAKE_OPTIONS = foreign

SUBDIRS = common src

if WITH_GNOME
SUBDIRS += auth-dialog properties po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-ipop-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-ipop-service.name

desktopfile = nm-ipop.desktop.in
iconfile = gnome-mime-application-x-ipop-settings.png

if WITH_GNOME
# FIXME: uncomment when nmce gets --import support
#desktopdir = $(datadir)/applications
#desktop_in_files = $(desktopfile)
#desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
#@INTLTOOL_DESKTOP_RULE@

#icondir = $(datadir)/icons/hicolor/48x48/apps
#icon_DATA = $(iconfile)
endif

nm-ipop-service.name: $(srcdir)/nm-ipop-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

DISTCHECK_CONFIGURE_FLAGS = \
	--with-tests=yes \
	--enable-more-warnings=yes

EXTRA_DIST = nm-ipop-service.name.in \
             $(dbusservice_DATA)  \
             $(desktopfile) \
             $(iconfile) \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in \
             nm-test-helpers.h

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
