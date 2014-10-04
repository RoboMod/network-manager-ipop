/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 * Copyright (C) 2008 Tambet Ingo, <tambet@gmail.com>
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

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib/gi18n-lib.h>
#include <nm-setting-connection.h>
#include <nm-setting-8021x.h>

#include "auth-helpers.h"
#include "nm-ipop.h"
#include "src/nm-ipop-service.h"
#include "common/utils.h"

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK    1
#define PW_TYPE_UNUSED 2

//static void
//show_password (GtkToggleButton *togglebutton, GtkEntry *password_entry)
//{
//	gtk_entry_set_visibility (password_entry, gtk_toggle_button_get_active (togglebutton));
//}

//static GtkWidget *
//setup_secret_widget (GtkBuilder *builder,
//                     const char *widget_name,
//                     NMSettingVPN *s_vpn,
//                     const char *secret_key)
//{
//	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
//	GtkWidget *widget;
//	GtkWidget *show_passwords;
//	const char *tmp;

//	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));
//	g_assert (widget);

//	show_passwords = GTK_WIDGET (gtk_builder_get_object (builder, "show_passwords"));
//	g_signal_connect (show_passwords, "toggled", G_CALLBACK (show_password), widget);

//	if (s_vpn) {
//		tmp = nm_setting_vpn_get_secret (s_vpn, secret_key);
//		if (tmp)
//			gtk_entry_set_text (GTK_ENTRY (widget), tmp);

//		nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_key, &pw_flags, NULL);
//		g_object_set_data (G_OBJECT (widget), "flags", GUINT_TO_POINTER (pw_flags));
//	}

//	return widget;
//}

//static void
//tls_cert_changed_cb (GtkWidget *widget, GtkWidget *next_widget)
//{
//	GtkFileChooser *this, *next;
//	char *fname, *next_fname;

//	/* If the just-changed file chooser is a PKCS#12 file, then all of the
//	 * TLS filechoosers have to be PKCS#12.  But if it just changed to something
//	 * other than a PKCS#12 file, then clear out the other file choosers.
//	 *
//	 * Basically, all the choosers have to contain PKCS#12 files, or none of
//	 * them can, because PKCS#12 files contain everything required for the TLS
//	 * connection (CA, client cert, private key).
//	 */

//	this = GTK_FILE_CHOOSER (widget);
//	next = GTK_FILE_CHOOSER (next_widget);

//	fname = gtk_file_chooser_get_filename (this);
//	if (is_pkcs12 (fname)) {
//		/* Make sure all choosers have this PKCS#12 file */
//		next_fname = gtk_file_chooser_get_filename (next);
//		if (!next_fname || strcmp (fname, next_fname)) {
//			/* Next chooser was different, make it the same as the first */
//			gtk_file_chooser_set_filename (next, fname);
//		}
//		g_free (fname);
//		g_free (next_fname);
//		return;
//	}
//	g_free (fname);

//	/* Just-chosen file isn't PKCS#12 or no file was chosen, so clear out other
//	 * file selectors that have PKCS#12 files in them.
//	 */
//	next_fname = gtk_file_chooser_get_filename (next);
//	if (is_pkcs12 (next_fname))
//		gtk_file_chooser_set_filename (next, NULL);
//	g_free (next_fname);
//}

//static void
//tls_setup (GtkBuilder *builder,
//           GtkSizeGroup *group,
//           NMSettingVPN *s_vpn,
//           const char *prefix,
//           GtkWidget *ca_chooser,
//           ChangedCallback changed_cb,
//           gpointer user_data)
//{
//	GtkWidget *widget, *cert, *key;
//	const char *value;
//	char *tmp;
//	GtkFileFilter *filter;

//	tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
//	cert = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	g_free (tmp);

//	gtk_size_group_add_widget (group, cert);
//	filter = tls_file_chooser_filter_new (TRUE);
//	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (cert), filter);
//	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (cert), TRUE);
//	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (cert),
//	                                   _("Choose your personal certificate..."));
//	g_signal_connect (G_OBJECT (cert), "selection-changed", G_CALLBACK (changed_cb), user_data);

//	if (s_vpn) {
//		value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_CERT);
//		if (value && strlen (value))
//			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (cert), value);
//	}

//	tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
//	key = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	g_free (tmp);

//	gtk_size_group_add_widget (group, key);
//	filter = tls_file_chooser_filter_new (TRUE);
//	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (key), filter);
//	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (key), TRUE);
//	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (key),
//	                                   _("Choose your private key..."));
//	g_signal_connect (G_OBJECT (key), "selection-changed", G_CALLBACK (changed_cb), user_data);

//	if (s_vpn) {
//		value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_KEY);
//		if (value && strlen (value))
//			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (key), value);
//	}

//	/* Link choosers to the PKCS#12 changer callback */
//	g_signal_connect (ca_chooser, "selection-changed", G_CALLBACK (tls_cert_changed_cb), cert);
//	g_signal_connect (cert, "selection-changed", G_CALLBACK (tls_cert_changed_cb), key);
//	g_signal_connect (key, "selection-changed", G_CALLBACK (tls_cert_changed_cb), ca_chooser);

//	/* Fill in the private key password */
//	tmp = g_strdup_printf ("%s_private_key_password_entry", prefix);
//	widget = setup_secret_widget (builder, tmp, s_vpn, NM_IPOP_KEY_CERTPASS);
//	g_free (tmp);
//	gtk_size_group_add_widget (group, widget);
//	g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), user_data);
//}

static void
pw_type_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
    GtkWidget *entry = user_data;

    /* If the user chose "Not required", desensitize and clear the correct
     * password entry.
     */
    switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
    case PW_TYPE_ASK:
    case PW_TYPE_UNUSED:
        gtk_entry_set_text (GTK_ENTRY (entry), "");
        gtk_widget_set_sensitive (entry, FALSE);
        break;
    default:
        gtk_widget_set_sensitive (entry, TRUE);
        break;
    }
}

//static
void
init_one_pw_combo (GtkBuilder *builder,
                   NMSettingVPN *s_vpn,
                   const char *secret_key,
                   GtkWidget *entry_widget,
                   ChangedCallback changed_cb,
                   gpointer user_data)
{
    int active = -1;
    GtkWidget *widget;
    GtkListStore *store;
    GtkTreeIter iter;
    const char *value = NULL;
    //char *tmp;
    guint32 default_idx = 1;
    NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;

    /* If there's already a password and the password type can't be found in
     * the VPN settings, default to saving it.  Otherwise, always ask for it.
     */
    value = gtk_entry_get_text (GTK_ENTRY (entry_widget));
    if (value && strlen (value))
        default_idx = 0;

    store = gtk_list_store_new (1, G_TYPE_STRING);
    if (s_vpn)
        nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_key, &pw_flags, NULL);

    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter, 0, _("Saved"), -1);
    if (   (active < 0)
        && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
        && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
        active = PW_TYPE_SAVE;
    }

    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter, 0, _("Always Ask"), -1);
    if ((active < 0) && (pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
        active = PW_TYPE_ASK;

    gtk_list_store_append (store, &iter);
    gtk_list_store_set (store, &iter, 0, _("Not Required"), -1);
    if ((active < 0) && (pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
        active = PW_TYPE_UNUSED;

    //tmp = g_strdup_printf ("%s_pass_type_combo", prefix);
    widget = GTK_WIDGET (gtk_builder_get_object (builder, "ipop-xmpp-password-type-combo"));
    g_assert (widget);
    //g_free (tmp);

    gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
    g_object_unref (store);
    gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? default_idx : active);
    pw_type_combo_changed_cb (widget, entry_widget);

    g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (pw_type_combo_changed_cb), entry_widget);
    g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
}

//static void
//pw_setup (GtkBuilder *builder,
//          GtkSizeGroup *group,
//          NMSettingVPN *s_vpn,
//          const char *prefix,
//          ChangedCallback changed_cb,
//          gpointer user_data)
//{
//	GtkWidget *widget;
//	const char *value;
//	char *tmp;

//	tmp = g_strdup_printf ("%s_username_entry", prefix);
//	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	g_free (tmp);
//	gtk_size_group_add_widget (group, widget);

//	if (s_vpn) {
//        value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_XMPP_USERNAME);
//		if (value && strlen (value))
//			gtk_entry_set_text (GTK_ENTRY (widget), value);
//	}
//	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

//	/* Fill in the user password */
//	tmp = g_strdup_printf ("%s_password_entry", prefix);
//    widget = setup_secret_widget (builder, tmp, s_vpn, NM_IPOP_KEY_XMPP_PASSWORD);
//	g_free (tmp);
//	gtk_size_group_add_widget (group, widget);
//	g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), user_data);

//    init_one_pw_combo (builder, s_vpn, prefix, NM_IPOP_KEY_XMPP_PASSWORD, widget, changed_cb, user_data);
//}

//void
//tls_pw_init_auth_widget (GtkBuilder *builder,
//                         GtkSizeGroup *group,
//                         NMSettingVPN *s_vpn,
//                         const char *contype,
//                         const char *prefix,
//                         ChangedCallback changed_cb,
//                         gpointer user_data)
//{
//	GtkWidget *ca;
//	const char *value;
//	char *tmp;
//	GtkFileFilter *filter;
//	gboolean tls = FALSE, pw = FALSE;

//	g_return_if_fail (builder != NULL);
//	g_return_if_fail (group != NULL);
//	g_return_if_fail (changed_cb != NULL);
//	g_return_if_fail (prefix != NULL);

//	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
//	ca = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	g_free (tmp);
//	gtk_size_group_add_widget (group, ca);

//	/* Three major connection types here: TLS-only, PW-only, and TLS + PW */
//	if (!strcmp (contype, NM_IPOP_CONTYPE_TLS) || !strcmp (contype, NM_IPOP_CONTYPE_PASSWORD_TLS))
//		tls = TRUE;
//	if (!strcmp (contype, NM_IPOP_CONTYPE_PASSWORD) || !strcmp (contype, NM_IPOP_CONTYPE_PASSWORD_TLS))
//		pw = TRUE;

//	/* Only TLS types can use PKCS#12 */
//	filter = tls_file_chooser_filter_new (tls);

//	/* Set up CA cert file picker which all connection types support */
//	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (ca), filter);
//	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (ca), TRUE);
//	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (ca),
//	                                   _("Choose a Certificate Authority certificate..."));
//	g_signal_connect (G_OBJECT (ca), "selection-changed", G_CALLBACK (changed_cb), user_data);

//	if (s_vpn) {
//		value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_CA);
//		if (value && strlen (value))
//			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (ca), value);
//	}

//	/* Set up the rest of the options */
//	if (tls)
//		tls_setup (builder, group, s_vpn, prefix, ca, changed_cb, user_data);
//	if (pw)
//		pw_setup (builder, group, s_vpn, prefix, changed_cb, user_data);
//}

//#define SK_DIR_COL_NAME 0
//#define SK_DIR_COL_NUM  1

//void
//sk_init_auth_widget (GtkBuilder *builder,
//                     GtkSizeGroup *group,
//                     NMSettingVPN *s_vpn,
//                     ChangedCallback changed_cb,
//                     gpointer user_data)
//{
//	GtkWidget *widget;
//	const char *value = NULL;
//	GtkListStore *store;
//	GtkTreeIter iter;
//	gint active = -1;
//	gint direction = -1;
//	GtkFileFilter *filter;

//	g_return_if_fail (builder != NULL);
//	g_return_if_fail (group != NULL);
//	g_return_if_fail (changed_cb != NULL);

//	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
//	gtk_size_group_add_widget (group, widget);
//	filter = sk_file_chooser_filter_new ();
//	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
//	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
//	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
//	                                   _("Choose an IPOP static key..."));
//	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

//	if (s_vpn) {
//		value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_STATIC_KEY);
//		if (value && strlen (value))
//			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
//	}

//	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

//	if (s_vpn) {
//		value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_STATIC_KEY_DIRECTION);
//		if (value && strlen (value)) {
//			long int tmp;

//			errno = 0;
//			tmp = strtol (value, NULL, 10);
//			if (errno == 0 && (tmp == 0 || tmp == 1))
//				direction = (guint32) tmp;
//		}
//	}

//	gtk_list_store_append (store, &iter);
//	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, _("None"), SK_DIR_COL_NUM, -1, -1);

//	gtk_list_store_append (store, &iter);
//	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "0", SK_DIR_COL_NUM, 0, -1);
//	if (direction == 0)
//		active = 1;

//	gtk_list_store_append (store, &iter);
//	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "1", SK_DIR_COL_NUM, 1, -1);
//	if (direction == 1)
//		active = 2;

//	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));
//	gtk_size_group_add_widget (group, widget);

//	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
//	g_object_unref (store);
//	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

//	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_dir_help_label"));
//	gtk_size_group_add_widget (group, widget);

//	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
//	gtk_size_group_add_widget (group, widget);
//	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
//	if (s_vpn) {
//		value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_LOCAL_IP);
//		if (value && strlen (value))
//			gtk_entry_set_text (GTK_ENTRY (widget), value);
//	}

//	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
//	gtk_size_group_add_widget (group, widget);
//	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
//	if (s_vpn) {
//		value = nm_setting_vpn_get_data_item (s_vpn, NM_IPOP_KEY_REMOTE_IP);
//		if (value && strlen (value))
//			gtk_entry_set_text (GTK_ENTRY (widget), value);
//	}
//}

//static gboolean
//validate_file_chooser (GtkBuilder *builder, const char *name)
//{
//	GtkWidget *widget;
//	char *str;
//	gboolean valid = FALSE;

//	widget = GTK_WIDGET (gtk_builder_get_object (builder, name));
//	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
//	if (str && strlen (str))
//		valid = TRUE;
//	g_free (str);
//	return valid;
//}

//static gboolean
//validate_tls (GtkBuilder *builder, const char *prefix, GError **error)
//{
//	char *tmp;
//	gboolean valid, encrypted = FALSE;
//	GtkWidget *widget;
//	char *str;

//	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
//	valid = validate_file_chooser (builder, tmp);
//	g_free (tmp);
//	if (!valid) {
//		g_set_error (error,
//		             IPOP_PLUGIN_UI_ERROR,
//		             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//		             NM_IPOP_KEY_CA);
//		return FALSE;
//	}

//	tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
//	valid = validate_file_chooser (builder, tmp);
//	g_free (tmp);
//	if (!valid) {
//		g_set_error (error,
//		             IPOP_PLUGIN_UI_ERROR,
//		             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//		             NM_IPOP_KEY_CERT);
//		return FALSE;
//	}

//	tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
//	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	valid = validate_file_chooser (builder, tmp);
//	g_free (tmp);
//	if (!valid) {
//		g_set_error (error,
//		             IPOP_PLUGIN_UI_ERROR,
//		             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//		             NM_IPOP_KEY_KEY);
//		return FALSE;
//	}

//	/* Encrypted certificates require a password */
//	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
//	encrypted = is_encrypted (str);
//	g_free (str);
//	if (encrypted) {
//		tmp = g_strdup_printf ("%s_private_key_password_entry", prefix);
//		widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//		g_free (tmp);

//		if (!gtk_entry_get_text_length (GTK_ENTRY (widget))) {
//			g_set_error (error,
//			             IPOP_PLUGIN_UI_ERROR,
//			             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//			             NM_IPOP_KEY_CERTPASS);
//			return FALSE;
//		}
//	}

//	return TRUE;
//}

//gboolean
//auth_widget_check_validity (GtkBuilder *builder, const char *contype, GError **error)
//{
//	GtkWidget *widget;
//	const char *str;

//	if (!strcmp (contype, NM_IPOP_CONTYPE_TLS)) {
//		if (!validate_tls (builder, "tls", error))
//			return FALSE;
//	} else if (!strcmp (contype, NM_IPOP_CONTYPE_PASSWORD_TLS)) {
//		if (!validate_tls (builder, "pw_tls", error))
//			return FALSE;

//		widget = GTK_WIDGET (gtk_builder_get_object (builder, "pw_tls_username_entry"));
//		str = gtk_entry_get_text (GTK_ENTRY (widget));
//		if (!str || !strlen (str)) {
//			g_set_error (error,
//			             IPOP_PLUGIN_UI_ERROR,
//			             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//			             NM_IPOP_KEY_USERNAME);
//			return FALSE;
//		}
//	} else if (!strcmp (contype, NM_IPOP_CONTYPE_PASSWORD)) {
//		if (!validate_file_chooser (builder, "pw_ca_cert_chooser")) {
//			g_set_error (error,
//			             IPOP_PLUGIN_UI_ERROR,
//			             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//			             NM_IPOP_KEY_CA);
//			return FALSE;
//		}
//		widget = GTK_WIDGET (gtk_builder_get_object (builder, "pw_username_entry"));
//		str = gtk_entry_get_text (GTK_ENTRY (widget));
//		if (!str || !strlen (str)) {
//			g_set_error (error,
//			             IPOP_PLUGIN_UI_ERROR,
//			             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//			             NM_IPOP_KEY_USERNAME);
//			return FALSE;
//		}
//	} else if (!strcmp (contype, NM_IPOP_CONTYPE_STATIC_KEY)) {
//		if (!validate_file_chooser (builder, "sk_key_chooser")) {
//			g_set_error (error,
//			             IPOP_PLUGIN_UI_ERROR,
//			             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//			             NM_IPOP_KEY_STATIC_KEY);
//			return FALSE;
//		}

//		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
//		str = gtk_entry_get_text (GTK_ENTRY (widget));
//		if (!str || !strlen (str)) {
//			g_set_error (error,
//			             IPOP_PLUGIN_UI_ERROR,
//			             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//			             NM_IPOP_KEY_LOCAL_IP);
//			return FALSE;
//		}

//		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
//		str = gtk_entry_get_text (GTK_ENTRY (widget));
//		if (!str || !strlen (str)) {
//			g_set_error (error,
//			             IPOP_PLUGIN_UI_ERROR,
//			             IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
//			             NM_IPOP_KEY_REMOTE_IP);
//			return FALSE;
//		}
//	} else
//		g_assert_not_reached ();

//	return TRUE;
//}

//static void
//update_from_filechooser (GtkBuilder *builder,
//                         const char *key,
//                         const char *prefix,
//                         const char *widget_name,
//                         NMSettingVPN *s_vpn)
//{
//	GtkWidget *widget;
//	char *tmp, *filename;

//	g_return_if_fail (builder != NULL);
//	g_return_if_fail (key != NULL);
//	g_return_if_fail (prefix != NULL);
//	g_return_if_fail (widget_name != NULL);
//	g_return_if_fail (s_vpn != NULL);

//	tmp = g_strdup_printf ("%s_%s", prefix, widget_name);
//	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	g_free (tmp);

//	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
//	if (filename && strlen (filename))
//		nm_setting_vpn_add_data_item (s_vpn, key, filename);
//	g_free (filename);
//}

//static void
//update_tls (GtkBuilder *builder, const char *prefix, NMSettingVPN *s_vpn)
//{
//	GtkWidget *widget;
//	NMSettingSecretFlags pw_flags;
//	char *tmp;
//	const char *str;

//	update_from_filechooser (builder, NM_IPOP_KEY_CA, prefix, "ca_cert_chooser", s_vpn);
//	update_from_filechooser (builder, NM_IPOP_KEY_CERT, prefix, "user_cert_chooser", s_vpn);
//	update_from_filechooser (builder, NM_IPOP_KEY_KEY, prefix, "private_key_chooser", s_vpn);

//	/* Password */
//	tmp = g_strdup_printf ("%s_private_key_password_entry", prefix);
//	widget = (GtkWidget *) gtk_builder_get_object (builder, tmp);
//	g_assert (widget);
//	g_free (tmp);

//	str = gtk_entry_get_text (GTK_ENTRY (widget));
//	if (str && strlen (str))
//		nm_setting_vpn_add_secret (s_vpn, NM_IPOP_KEY_CERTPASS, str);

//	pw_flags = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (widget), "flags"));
//	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_IPOP_KEY_CERTPASS, pw_flags, NULL);
//}

//static void
//update_pw (GtkBuilder *builder, const char *prefix, NMSettingVPN *s_vpn)
//{
//	GtkWidget *widget;
//	NMSettingSecretFlags pw_flags;
//	char *tmp;
//	const char *str;

//	g_return_if_fail (builder != NULL);
//	g_return_if_fail (prefix != NULL);
//	g_return_if_fail (s_vpn != NULL);

//	tmp = g_strdup_printf ("%s_username_entry", prefix);
//	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	g_free (tmp);

//	str = gtk_entry_get_text (GTK_ENTRY (widget));
//	if (str && strlen (str))
//        nm_setting_vpn_add_data_item (s_vpn, NM_IPOP_KEY_XMPP_USERNAME, str);

//	/* Password */
//	tmp = g_strdup_printf ("%s_password_entry", prefix);
//	widget = (GtkWidget *) gtk_builder_get_object (builder, tmp);
//	g_assert (widget);
//	g_free (tmp);

//	str = gtk_entry_get_text (GTK_ENTRY (widget));
//	if (str && strlen (str))
//        nm_setting_vpn_add_secret (s_vpn, NM_IPOP_KEY_XMPP_PASSWORD, str);

//	/* Update password flags */
//	pw_flags = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (widget), "flags"));
//	pw_flags &= ~(NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);

//	tmp = g_strdup_printf ("%s_pass_type_combo", prefix);
//	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
//	g_free (tmp);

//	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
//	case PW_TYPE_SAVE:
//		break;
//	case PW_TYPE_UNUSED:
//		pw_flags |= NM_SETTING_SECRET_FLAG_NOT_REQUIRED;
//		break;
//	case PW_TYPE_ASK:
//	default:
//		pw_flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
//		break;
//	}

//    nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_IPOP_KEY_XMPP_PASSWORD, pw_flags, NULL);
//}

//gboolean
//auth_widget_update_connection (GtkBuilder *builder,
//                               const char *contype,
//                               NMSettingVPN *s_vpn)
//{
//	GtkTreeModel *model;
//	GtkTreeIter iter;
//	GtkWidget *widget;
//	const char *str;

//	if (!strcmp (contype, NM_IPOP_CONTYPE_TLS)) {
//		update_tls (builder, "tls", s_vpn);
//	} else if (!strcmp (contype, NM_IPOP_CONTYPE_PASSWORD)) {
//		update_from_filechooser (builder, NM_IPOP_KEY_CA, "pw", "ca_cert_chooser", s_vpn);
//		update_pw (builder, "pw", s_vpn);
//	} else if (!strcmp (contype, NM_IPOP_CONTYPE_PASSWORD_TLS)) {
//		update_tls (builder, "pw_tls", s_vpn);
//		update_pw (builder, "pw_tls", s_vpn);
//	} else if (!strcmp (contype, NM_IPOP_CONTYPE_STATIC_KEY)) {
//		/* Update static key */
//		update_from_filechooser (builder, NM_IPOP_KEY_STATIC_KEY, "sk", "key_chooser", s_vpn);

//		/* Update direction */
//		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));
//		g_assert (widget);
//		model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
//		if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
//			int direction = -1;

//			gtk_tree_model_get (model, &iter, SK_DIR_COL_NUM, &direction, -1);
//			if (direction > -1) {
//				char *tmp = g_strdup_printf ("%d", direction);
//				nm_setting_vpn_add_data_item (s_vpn, NM_IPOP_KEY_STATIC_KEY_DIRECTION, tmp);
//				g_free (tmp);
//			}
//		}

//		/* Update local address */
//		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
//		g_assert (widget);
//		str = gtk_entry_get_text (GTK_ENTRY (widget));
//		if (str && strlen (str))
//			nm_setting_vpn_add_data_item (s_vpn, NM_IPOP_KEY_LOCAL_IP, str);

//		/* Update remote address */
//		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
//		g_assert (widget);
//		str = gtk_entry_get_text (GTK_ENTRY (widget));
//		if (str && strlen (str))
//			nm_setting_vpn_add_data_item (s_vpn, NM_IPOP_KEY_REMOTE_IP, str);
//	} else
//		g_assert_not_reached ();

//	return TRUE;
//}

//static const char *
//find_tag (const char *tag, const char *buf, gsize len)
//{
//	gsize i, taglen;

//	taglen = strlen (tag);
//	if (len < taglen)
//		return NULL;

//	for (i = 0; i < len - taglen + 1; i++) {
//		if (memcmp (buf + i, tag, taglen) == 0)
//			return buf + i;
//	}
//	return NULL;
//}

//static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
//static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
//static const char *pem_pkcs8_key_begin = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
//static const char *pem_cert_begin = "-----BEGIN CERTIFICATE-----";
//static const char *pem_unenc_key_begin = "-----BEGIN PRIVATE KEY-----";

//static gboolean
//tls_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
//{
//	char *contents = NULL, *p, *ext;
//	gsize bytes_read = 0;
//	gboolean show = FALSE;
////	gboolean pkcs_allowed = GPOINTER_TO_UINT (data);
//	struct stat statbuf;

//	if (!filter_info->filename)
//		return FALSE;

//	p = strrchr (filter_info->filename, '.');
//	if (!p)
//		return FALSE;

//	ext = g_ascii_strdown (p, -1);
//	if (!ext)
//		return FALSE;

////	if (pkcs_allowed && !strcmp (ext, ".p12") && is_pkcs12 (filter_info->filename)) {
////		g_free (ext);
////		return TRUE;
////	}

//	if (strcmp (ext, ".pem") && strcmp (ext, ".crt") && strcmp (ext, ".key") && strcmp (ext, ".cer")) {
//		g_free (ext);
//		return FALSE;
//	}
//	g_free (ext);

//	/* Ignore files that are really large */
//	if (!stat (filter_info->filename, &statbuf)) {
//		if (statbuf.st_size > 500000)
//			return FALSE;
//	}

//	if (!g_file_get_contents (filter_info->filename, &contents, &bytes_read, NULL))
//		return FALSE;

//	if (bytes_read < 400)  /* needs to be lower? */
//		goto out;

//	/* Check for PEM signatures */
//	if (find_tag (pem_rsa_key_begin, (const char *) contents, bytes_read)) {
//		show = TRUE;
//		goto out;
//	}

//	if (find_tag (pem_dsa_key_begin, (const char *) contents, bytes_read)) {
//		show = TRUE;
//		goto out;
//	}

//	if (find_tag (pem_cert_begin, (const char *) contents, bytes_read)) {
//		show = TRUE;
//		goto out;
//	}

//	if (find_tag (pem_pkcs8_key_begin, (const char *) contents, bytes_read)) {
//		show = TRUE;
//		goto out;
//	}

//	if (find_tag (pem_unenc_key_begin, (const char *) contents, bytes_read)) {
//		show = TRUE;
//		goto out;
//	}

//out:
//	g_free (contents);
//	return show;
//}

//GtkFileFilter *
//tls_file_chooser_filter_new (gboolean pkcs_allowed)
//{
//	GtkFileFilter *filter;

//	filter = gtk_file_filter_new ();
//	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, tls_default_filter, GUINT_TO_POINTER (pkcs_allowed), NULL);
//	gtk_file_filter_set_name (filter, pkcs_allowed ? _("PEM or PKCS#12 certificates (*.pem, *.crt, *.key, *.cer, *.p12)")
//	                                               : _("PEM certificates (*.pem, *.crt, *.key, *.cer)"));
//	return filter;
//}


//static const char *sk_key_begin = "-----BEGIN IPOP Static key V1-----";

//static gboolean
//sk_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
//{
//	int fd;
//	unsigned char buffer[1024];
//	ssize_t bytes_read;
//	gboolean show = FALSE;
//	char *p;
//	char *ext;

//	if (!filter_info->filename)
//		return FALSE;

//	p = strrchr (filter_info->filename, '.');
//	if (!p)
//		return FALSE;

//	ext = g_ascii_strdown (p, -1);
//	if (!ext)
//		return FALSE;
//	if (strcmp (ext, ".key")) {
//		g_free (ext);
//		return FALSE;
//	}
//	g_free (ext);

//	fd = open (filter_info->filename, O_RDONLY);
//	if (fd < 0)
//		return FALSE;

//	bytes_read = read (fd, buffer, sizeof (buffer) - 1);
//	if (bytes_read < 400)  /* needs to be lower? */
//		goto out;
//	buffer[bytes_read] = '\0';

//	/* Check for PEM signatures */
//	if (find_tag (sk_key_begin, (const char *) buffer, bytes_read)) {
//		show = TRUE;
//		goto out;
//	}

//out:
//	close (fd);
//	return show;
//}

//GtkFileFilter *
//sk_file_chooser_filter_new (void)
//{
//	GtkFileFilter *filter;

//	filter = gtk_file_filter_new ();
//	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, sk_default_filter, NULL, NULL);
//	gtk_file_filter_set_name (filter, _("IPOP Static Keys (*.key)"));
//	return filter;
//}

//static const char *advanced_keys[] = {
//    NM_IPOP_KEY_IP4_ADDRESS,
//    NM_IPOP_KEY_IP4_NETMASK,
//    NM_IPOP_KEY_XMPP_HOST,
//    NM_IPOP_KEY_XMPP_USERNAME,
//    NM_IPOP_KEY_XMPP_PASSWORD,
//    NULL
//};

//static void
//copy_values (const char *key, const char *value, gpointer user_data)
//{
//    GHashTable *hash = (GHashTable *) user_data;
//    const char **i;

//    for (i = &advanced_keys[0]; *i; i++) {
//        if (strcmp (key, *i))
//            continue;

//        g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
//    }
//}

//GHashTable *
//advanced_dialog_new_hash_from_connection (NMConnection *connection,
//                                          GError **error)
//{
//    GHashTable *hash;
//    NMSettingVPN *s_vpn;
//    //const char *secret;

//    hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

//    s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
//    nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

//    /* HTTP Proxy password is special */
//    /*secret = nm_setting_vpn_get_secret (s_vpn, NM_IPOP_KEY_HTTP_PROXY_PASSWORD);
//    if (secret) {
//        g_hash_table_insert (hash,
//                             g_strdup (NM_IPOP_KEY_HTTP_PROXY_PASSWORD),
//                             g_strdup (secret));
//    }*/

//    return hash;
//}


//GHashTable *
//advanced_dialog_new_hash_from_dialog(GtkWidget *dialog, GError **error)
//{
//	GHashTable *hash;
//	GtkWidget *widget;
//    GtkBuilder *builder;

//	g_return_val_if_fail (dialog != NULL, NULL);
//	if (error)
//		g_return_val_if_fail (*error == NULL, NULL);

//	builder = g_object_get_data (G_OBJECT (dialog), "builder");
//	g_return_val_if_fail (builder != NULL, NULL);

//	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

//	return hash;
//}

