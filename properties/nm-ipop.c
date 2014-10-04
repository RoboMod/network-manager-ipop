/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id: nm-ipop.c 4232 2008-10-29 09:13:40Z tambeti $
 *
 * nm-ipop.c : GNOME UI dialogs for configuring ipop VPN connections
 *
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 * Based on work by David Zeuthen, <davidz@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-ipop-service.h"
#include "nm-ipop.h"
#include "auth-helpers.h"
#include "import-export.h"

#define IPOP_PLUGIN_NAME    _("IPOP")
#define IPOP_PLUGIN_DESC    _("P2P connection via XMPP.")
#define IPOP_PLUGIN_SERVICE NM_DBUS_SERVICE_IPOP 


/************** plugin class **************/

static void ipop_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (IPOPPluginUi, ipop_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   ipop_plugin_ui_interface_init))

/************** UI widget class **************/

static void ipop_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (IPOPPluginUiWidget, ipop_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   ipop_plugin_ui_widget_interface_init))

#define IPOP_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), IPOP_TYPE_PLUGIN_UI_WIDGET, IPOPPluginUiWidgetPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
	gboolean new_connection;
} IPOPPluginUiWidgetPrivate;


#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

GQuark ipop_plugin_ui_error_quark(void) {
	static GQuark error_quark = 0;

    if (G_UNLIKELY(error_quark == 0))
        error_quark = g_quark_from_static_string("ipop-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType ipop_plugin_ui_error_get_type(void) {
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
            ENUM_ENTRY(IPOP_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The connection was missing invalid. */
            ENUM_ENTRY(IPOP_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The specified property was invalid. */
            ENUM_ENTRY(IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
            ENUM_ENTRY(IPOP_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The file to import could not be read. */
            ENUM_ENTRY(IPOP_PLUGIN_UI_ERROR_FILE_NOT_READABLE, "FileNotReadable"),
			/* The file to import could was not an IPOP client file. */
            ENUM_ENTRY(IPOP_PLUGIN_UI_ERROR_FILE_NOT_IPOP, "FileNotIPOP"),
			{ 0, 0, 0 }
		};
        etype = g_enum_register_static("IPOPPluginUiError", values);
	}
	return etype;
}

static gboolean check_validity(IPOPPluginUiWidget* self, GError** error) {
    IPOPPluginUiWidgetPrivate* priv = IPOP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    GtkWidget* widget;
    const char* str;

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-host"));
    str = gtk_entry_get_text(GTK_ENTRY(widget));
    if (!str || !strlen(str)) {
        g_set_error(error,
                    IPOP_PLUGIN_UI_ERROR,
                    IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
                    NM_IPOP_KEY_XMPP_HOST);
		return FALSE;
	}

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-username"));
    str = gtk_entry_get_text(GTK_ENTRY(widget));
    if (!str || !strlen(str)) {
        g_set_error(error,
                    IPOP_PLUGIN_UI_ERROR,
                    IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
                    NM_IPOP_KEY_XMPP_USERNAME);
        return FALSE;
    }

	return TRUE;
}

static void stuff_changed_cb(GtkWidget* widget, gpointer user_data) {
    g_signal_emit_by_name(IPOP_PLUGIN_UI_WIDGET(user_data), "changed");
}

static gboolean init_plugin_ui(IPOPPluginUiWidget* self, NMConnection* connection,
                               GError** error) {
    IPOPPluginUiWidgetPrivate* priv = IPOP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    NMSettingVPN* s_vpn;
    GtkWidget* widget;
    const char* value;

    s_vpn = nm_connection_get_setting_vpn(connection);

    priv->group = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-host"));
    g_return_val_if_fail(widget != NULL, FALSE);
    gtk_size_group_add_widget(priv->group, widget);
	if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_HOST);
		if (value)
            gtk_entry_set_text(GTK_ENTRY(widget), value);
	}
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(stuff_changed_cb), self);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-username"));
    g_return_val_if_fail(widget != NULL, FALSE);
    gtk_size_group_add_widget(priv->group, widget);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_USERNAME);
        if (value)
            gtk_entry_set_text(GTK_ENTRY(widget), value);
    }
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(stuff_changed_cb), self);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-password"));
    g_return_val_if_fail(widget != NULL, FALSE);
    gtk_size_group_add_widget(priv->group, widget);
    if (s_vpn) {
        value = nm_setting_vpn_get_secret(s_vpn, NM_IPOP_KEY_XMPP_PASSWORD);
        if (value)
            gtk_entry_set_text(GTK_ENTRY(widget), value);
    }
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(stuff_changed_cb), self);

    init_one_pw_combo(priv->builder, s_vpn, NM_IPOP_KEY_XMPP_PASSWORD, widget,
                      stuff_changed_cb, self);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-ip-address"));
    g_return_val_if_fail(widget != NULL, FALSE);
    gtk_size_group_add_widget(priv->group, widget);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_IP4_ADDRESS);
        if (value && strlen(value))
            gtk_entry_set_text (GTK_ENTRY(widget), value);
        else if (priv->new_connection)
            gtk_entry_set_text (GTK_ENTRY(widget), "172.31.0.100");
    }
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(stuff_changed_cb), self);

    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-ip-netmask"));
    g_return_val_if_fail(widget != NULL, FALSE);
    gtk_size_group_add_widget(priv->group, widget);
    if (s_vpn) {
        value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_IP4_NETMASK);
        if (value && strlen(value))
            gtk_entry_set_text(GTK_ENTRY(widget), value);
        else if (priv->new_connection)
            gtk_entry_set_text(GTK_ENTRY(widget), "255.255.255.0");
    }
    g_signal_connect(G_OBJECT(widget), "changed", G_CALLBACK(stuff_changed_cb), self);

	return TRUE;
}

static GObject* get_widget(NMVpnPluginUiWidgetInterface* iface) {
    IPOPPluginUiWidget *self = IPOP_PLUGIN_UI_WIDGET(iface);
    IPOPPluginUiWidgetPrivate *priv = IPOP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);

    return G_OBJECT(priv->widget);
}

static gboolean update_connection (NMVpnPluginUiWidgetInterface* iface,
                                   NMConnection* connection, GError** error) {
    IPOPPluginUiWidget* self = IPOP_PLUGIN_UI_WIDGET(iface);
    IPOPPluginUiWidgetPrivate* priv = IPOP_PLUGIN_UI_WIDGET_GET_PRIVATE(self);
    NMSettingVPN* s_vpn;
    GtkWidget* widget;
    char* str;
	gboolean valid = FALSE;

    if (!check_validity(self, error))
		return FALSE;

    s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_IPOP, NULL);

    /* xmpp host */
    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-host"));
    str = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && strlen(str))
        nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_XMPP_HOST, str);

    /* xmpp username */
    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-username"));
    str = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && strlen(str))
        nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_XMPP_USERNAME, str);

    /* xmpp password */
    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-xmpp-password"));
    str = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && strlen(str))
        nm_setting_vpn_add_secret(s_vpn, NM_IPOP_KEY_XMPP_PASSWORD, str);

	/* Default to agent-owned secrets for new connections */
    if (priv->new_connection) {
        if (nm_setting_vpn_get_secret(s_vpn, NM_IPOP_KEY_XMPP_PASSWORD)) {
            nm_setting_set_secret_flags(NM_SETTING(s_vpn),
                                        NM_IPOP_KEY_XMPP_PASSWORD,
                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                        NULL);
		}
	}

    /* ip4 address */
    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-ip-address"));
    str = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && strlen(str))
        nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_IP4_ADDRESS, str);

    /* ip4 netmask */
    widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-ip-netmask"));
    str = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
    if (str && strlen(str))
        nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_IP4_NETMASK, str);

    nm_connection_add_setting(connection, NM_SETTING(s_vpn));
	valid = TRUE;

	return valid;
}

static void is_new_func(const char* key, const char* value, gpointer user_data) {
    gboolean* is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

static NMVpnPluginUiWidgetInterface* nm_vpn_plugin_ui_widget_interface_new(
        NMConnection* connection, GError** error) {
    NMVpnPluginUiWidgetInterface* object;
    IPOPPluginUiWidgetPrivate* priv;
    char* ui_file;
	gboolean new = TRUE;
    NMSettingVPN* s_vpn;

	if (error)
        g_return_val_if_fail(*error == NULL, NULL);

    object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE(g_object_new(IPOP_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
        g_set_error(error, IPOP_PLUGIN_UI_ERROR, 0, "could not create ipop ui object");
		return NULL;
	}

    priv = IPOP_PLUGIN_UI_WIDGET_GET_PRIVATE(object);

    ui_file = g_strdup_printf("%s/%s", UIDIR, "nm-ipop-dialog.ui");
    priv->builder = gtk_builder_new();

    gtk_builder_set_translation_domain(priv->builder, GETTEXT_PACKAGE);

    if (!gtk_builder_add_from_file(priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
        g_clear_error(error);
        g_set_error(error, IPOP_PLUGIN_UI_ERROR, 0,
		             "could not load required resources from %s", ui_file);
        g_free(ui_file);
        g_object_unref(object);
		return NULL;
	}

    g_free(ui_file);

    priv->widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "ipop-vbox"));
	if (!priv->widget) {
        g_set_error(error, IPOP_PLUGIN_UI_ERROR, 0, "could not load UI widget");
        g_object_unref(object);
		return NULL;
	}
    g_object_ref_sink(priv->widget);

    priv->window_group = gtk_window_group_new();

    s_vpn = nm_connection_get_setting_vpn(connection);
	if (s_vpn)
        nm_setting_vpn_foreach_data_item(s_vpn, is_new_func, &new);
	priv->new_connection = new;

    if (!init_plugin_ui(IPOP_PLUGIN_UI_WIDGET(object), connection, error)) {
        g_object_unref(object);
		return NULL;
	}

	return object;
}

static void dispose(GObject* object) {
    IPOPPluginUiWidget* plugin = IPOP_PLUGIN_UI_WIDGET(object);
    IPOPPluginUiWidgetPrivate* priv = IPOP_PLUGIN_UI_WIDGET_GET_PRIVATE(plugin);

	if (priv->group)
        g_object_unref(priv->group);

	if (priv->window_group)
        g_object_unref(priv->window_group);

	if (priv->widget)
        g_object_unref(priv->widget);

	if (priv->builder)
        g_object_unref(priv->builder);

	if (priv->advanced)
        g_hash_table_destroy(priv->advanced);

    G_OBJECT_CLASS(ipop_plugin_ui_widget_parent_class)->dispose(object);
}

static void ipop_plugin_ui_widget_class_init(IPOPPluginUiWidgetClass* req_class) {
    GObjectClass* object_class = G_OBJECT_CLASS(req_class);

    g_type_class_add_private(req_class, sizeof(IPOPPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void ipop_plugin_ui_widget_init (IPOPPluginUiWidget* plugin) {}

static void ipop_plugin_ui_widget_interface_init(NMVpnPluginUiWidgetInterface* iface_class) {
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static NMConnection* import(NMVpnPluginUiInterface* iface, const char* path, GError** error) {
    NMConnection* connection = NULL;
    char* contents = NULL;
    char** lines = NULL;
    char* ext;

    ext = strrchr(path, '.');
	if (!ext) {
        g_set_error(error,
                    IPOP_PLUGIN_UI_ERROR,
                    IPOP_PLUGIN_UI_ERROR_FILE_NOT_IPOP,
                    "unknown IPOP file extension");
		goto out;
	}

    connection = do_import(path, error);

out:
	if (lines)
        g_strfreev(lines);
    g_free(contents);

	return connection;
}

static gboolean export(NMVpnPluginUiInterface* iface, const char* path, NMConnection* connection,
                       GError** error) {
    return do_export(path, connection, error);
}

static char* get_suggested_name(NMVpnPluginUiInterface* iface, NMConnection* connection) {
    NMSettingConnection* s_con;
    const char* id;

    g_return_val_if_fail(connection != NULL, NULL);

    s_con = NM_SETTING_CONNECTION(nm_connection_get_setting(connection, NM_TYPE_SETTING_CONNECTION));
    g_return_val_if_fail(s_con != NULL, NULL);

    id = nm_setting_connection_get_id(s_con);
    g_return_val_if_fail(id != NULL, NULL);

    return g_strdup_printf("%s (ipop).conf", id);
}

static guint32 get_capabilities (NMVpnPluginUiInterface* iface) {
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static NMVpnPluginUiWidgetInterface* ui_factory(NMVpnPluginUiInterface* iface,
                                                NMConnection* connection, GError** error) {
    return nm_vpn_plugin_ui_widget_interface_new(connection, error);
}

static void get_property(GObject* object, guint prop_id, GValue* value, GParamSpec* pspec) {
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
        g_value_set_string(value, IPOP_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
        g_value_set_string(value, IPOP_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
        g_value_set_string(value, IPOP_PLUGIN_SERVICE);
		break;
	default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
		break;
	}
}

static void ipop_plugin_ui_class_init(IPOPPluginUiClass* req_class) {
    GObjectClass *object_class = G_OBJECT_CLASS(req_class);

	object_class->get_property = get_property;

    g_object_class_override_property(object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

    g_object_class_override_property(object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

    g_object_class_override_property(object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void ipop_plugin_ui_init(IPOPPluginUi* plugin) {}

static void ipop_plugin_ui_interface_init(NMVpnPluginUiInterface* iface_class) {
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
	iface_class->export_to_file = export;
	iface_class->get_suggested_name = get_suggested_name;
}

G_MODULE_EXPORT NMVpnPluginUiInterface* nm_vpn_plugin_ui_factory(GError** error) {
	if (error)
        g_return_val_if_fail(*error == NULL, NULL);

    return NM_VPN_PLUGIN_UI_INTERFACE(g_object_new (IPOP_TYPE_PLUGIN_UI, NULL));
}
