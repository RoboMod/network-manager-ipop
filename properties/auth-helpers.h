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

#ifndef _AUTH_HELPERS_H_
#define _AUTH_HELPERS_H_

#include <glib.h>
#include <gtk/gtk.h>

#include <nm-connection.h>
#include <nm-setting-vpn.h>

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

void init_one_pw_combo(GtkBuilder *builder,
                   NMSettingVPN *s_vpn,
                   const char *secret_key,
                   GtkWidget *entry_widget,
                   ChangedCallback changed_cb,
                   gpointer user_data);

#endif
