AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(NM_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-I$(top_srcdir)

libexec_PROGRAMS = nm-ipop-service nm-ipop-service-ipop-helper

nm_ipop_service_SOURCES = \
	nm-ipop-service.c \
	nm-ipop-service.h

nm_ipop_service_LDADD = \
	$(NM_LIBS) \
        $(top_builddir)/common/libnm-ipop-common.la

nm_ipop_service_ipop_helper_SOURCES = \
	nm-ipop-service-ipop-helper.c

nm_ipop_service_ipop_helper_LDADD = \
	$(DBUS_LIBS) \
	$(NM_LIBS)

CLEANFILES = *~
