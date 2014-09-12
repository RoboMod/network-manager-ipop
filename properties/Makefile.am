SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-ipop-properties.la

libnm_ipop_properties_la_SOURCES = \
	nm-ipop.c \
	nm-ipop.h \
	auth-helpers.c \
	auth-helpers.h 
		
#	import-export.c \
#	import-export.h

uidir = $(datadir)/gnome-vpn-properties/ipop
ui_DATA = nm-ipop-dialog.ui

libnm_ipop_properties_la_CFLAGS =                    \
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                       \
        $(GNOMEKEYRING_CFLAGS)                          \
        $(DISABLE_DEPRECATED)                           \
        -I$(top_srcdir)/                                \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"          \
        -DVERSION=\"$(VERSION)\"

libnm_ipop_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS) \
        $(top_builddir)/common/libnm-ipop-common.la

libnm_ipop_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
