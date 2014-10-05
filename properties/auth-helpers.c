/* auth-helpers.h: helpers for password management in properties
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2014 Andreas Ihrig <mod.andy@gmx.de>
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
 */


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

static void pw_type_combo_changed_cb(GtkWidget *combo, gpointer user_data) {
    GtkWidget *entry = user_data;

    /* If the user chose "Not required", desensitize and clear the correct
     * password entry.
     */
    switch (gtk_combo_box_get_active(GTK_COMBO_BOX(combo))) {
        case PW_TYPE_ASK:
        case PW_TYPE_UNUSED:
            gtk_entry_set_text(GTK_ENTRY(entry), "");
            gtk_widget_set_sensitive(entry, FALSE);
            break;
        default:
            gtk_widget_set_sensitive(entry, TRUE);
            break;
    }
}

void init_one_pw_combo(GtkBuilder *builder, NMSettingVPN *s_vpn,
                       const char *secret_key, GtkWidget *entry_widget,
                       ChangedCallback changed_cb, gpointer user_data) {
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
    value = gtk_entry_get_text(GTK_ENTRY(entry_widget));
    if (value && strlen(value))
        default_idx = 0;

    store = gtk_list_store_new(1, G_TYPE_STRING);
    if (s_vpn)
        nm_setting_get_secret_flags(NM_SETTING(s_vpn), secret_key, &pw_flags, NULL);

    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, _("Saved"), -1);
    if (   (active < 0)
        && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
        && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
        active = PW_TYPE_SAVE;
    }

    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, _("Always Ask"), -1);
    if ((active < 0) && (pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
        active = PW_TYPE_ASK;

    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, _("Not Required"), -1);
    if ((active < 0) && (pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
        active = PW_TYPE_UNUSED;

    //tmp = g_strdup_printf ("%s_pass_type_combo", prefix);
    widget = GTK_WIDGET(gtk_builder_get_object (builder, "ipop-xmpp-password-type-combo"));
    g_assert (widget);
    //g_free (tmp);

    gtk_combo_box_set_model(GTK_COMBO_BOX(widget), GTK_TREE_MODEL(store));
    g_object_unref(store);
    gtk_combo_box_set_active(GTK_COMBO_BOX(widget), active < 0 ? default_idx : active);
    pw_type_combo_changed_cb(widget, entry_widget);

    g_signal_connect(G_OBJECT(widget), "changed",
                     G_CALLBACK(pw_type_combo_changed_cb), entry_widget);
    g_signal_connect(G_OBJECT(widget), "changed",
                     G_CALLBACK(changed_cb), user_data);
}
