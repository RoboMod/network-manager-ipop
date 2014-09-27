AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(NM_CFLAGS) \
	$(GIO_CFLAGS) \
	$(JSON_CFLAGS) \
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

libexec_PROGRAMS = nm-ipop-service

nm_ipop_service_SOURCES = \
	nm-ipop-service.c \
	nm-ipop-service.h

nm_ipop_service_LDADD = \
	$(NM_LIBS) \
	$(GIO_LIBS) \
	$(JSON_LIBS) \
        $(top_builddir)/common/libnm-ipop-common.la

CLEANFILES = *~
