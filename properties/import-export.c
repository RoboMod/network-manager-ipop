/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
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
 * Copyright (C) 2008 - 2011 Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
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
#include <ctype.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <glib/gi18n-lib.h>
#include <glib/gprintf.h>
#include <json-glib/json-glib.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "import-export.h"
#include "nm-utils.h"
#include "nm-ipop.h"
#include "../src/nm-ipop-service.h"
#include "../common/utils.h"

#define XMPP_HOST_TAG "xmpp_host"
#define XMPP_USERNAME_TAG "xmpp_username"
#define XMPP_PASSWORD_TAG "xmpp_password"
#define IP4_ADDRESS_TAG "ip4"
#define IP4_NETMASK_TAG "ip4_mask"

NMConnection* do_import(const char* path, GError** error) {
    NMConnection* connection = NULL;
    NMSettingConnection* s_con;
    NMSettingVPN* s_vpn;
    char *last_dot;
    gboolean have_pass = FALSE;
    char *basename;
    JsonParser* json_parser;
    JsonReader* json_reader;

    connection = nm_connection_new();
    s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());
    nm_connection_add_setting(connection, NM_SETTING(s_con));

    s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());

    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_IPOP, NULL);

    // set connection id from file name
    basename = g_path_get_basename(path);
    last_dot = strrchr(basename, '.');
	if (last_dot)
		*last_dot = '\0';
    g_object_set(s_con, NM_SETTING_CONNECTION_ID, basename, NULL);
    g_free(basename);

    json_parser = json_parser_new();
    if (json_parser_load_from_file(json_parser, path, error)) {
        json_reader = json_reader_new(json_parser_get_root(json_parser));

        if(json_reader_read_member(json_reader, XMPP_HOST_TAG)) {
            nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_XMPP_HOST, json_reader_get_string_value(json_reader));
        }
        json_reader_end_member(json_reader);

        if(json_reader_read_member(json_reader, XMPP_USERNAME_TAG)) {
            nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_XMPP_USERNAME, json_reader_get_string_value(json_reader));
        }
        json_reader_end_member(json_reader);

        if(json_reader_read_member(json_reader, XMPP_PASSWORD_TAG)) {
            nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_XMPP_PASSWORD, json_reader_get_string_value(json_reader));
            have_pass = TRUE;
        }
        json_reader_end_member(json_reader);

        if(json_reader_read_member(json_reader, IP4_ADDRESS_TAG)) {
            nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_IP4_ADDRESS, json_reader_get_string_value(json_reader));
        }
        json_reader_end_member(json_reader);

        if(json_reader_read_member(json_reader, IP4_NETMASK_TAG)) {
            nm_setting_vpn_add_data_item(s_vpn, NM_IPOP_KEY_IP4_NETMASK,
                                g_strdup_printf("%d", (int)json_reader_get_int_value(json_reader)));
        }
        json_reader_end_member(json_reader);
    } else {
        g_set_error(error,
                    IPOP_PLUGIN_UI_ERROR,
                    IPOP_PLUGIN_UI_ERROR_FILE_NOT_IPOP,
                    "The file to import wasn't a valid IPOP configuration.");
        g_object_unref(connection);
        connection = NULL;
    }

    /* Default secret flags to be agent-owned */
    if (have_pass) {
        nm_setting_set_secret_flags(NM_SETTING(s_vpn),
                                    NM_IPOP_KEY_XMPP_PASSWORD,
                                    NM_SETTING_SECRET_FLAG_AGENT_OWNED,
                                    NULL);
    }
    else {
        nm_setting_set_secret_flags(NM_SETTING(s_vpn),
                                    NM_IPOP_KEY_XMPP_PASSWORD,
                                    NM_SETTING_SECRET_FLAG_NOT_SAVED,
                                    NULL);
    }

	if (connection)
        nm_connection_add_setting(connection, NM_SETTING(s_vpn));
	else if (s_vpn)
        g_object_unref(s_vpn);

	return connection;
}

gboolean do_export(const char* path, NMConnection* connection, GError** error) {
    NMSettingConnection* s_con;
    NMSettingVPN* s_vpn;
    FILE* f;
    JsonBuilder* json_builder;
    JsonGenerator* json_generator;
    JsonNode* json_root;
    const char* value;
    int netmask;
    gboolean success = FALSE;

    s_con = NM_SETTING_CONNECTION(nm_connection_get_setting(connection, NM_TYPE_SETTING_CONNECTION));
    g_assert(s_con);

    s_vpn = (NMSettingVPN*)nm_connection_get_setting(connection, NM_TYPE_SETTING_VPN);

    // check if file is writable
    f = fopen(path, "w");
	if (!f) {
        g_set_error(error, 0, 0, "could not open file for writing");
		return FALSE;
	}
    fclose(f);

    json_builder = json_builder_new();
    json_builder_begin_object(json_builder);

    value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_HOST);
    if (value && strlen(value)) {
        json_builder_set_member_name(json_builder, XMPP_HOST_TAG);
        json_builder_add_string_value(json_builder, value);
    }

    value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_USERNAME);
    if (value && strlen(value)) {
        json_builder_set_member_name(json_builder, XMPP_USERNAME_TAG);
        json_builder_add_string_value(json_builder, value);
    }

    value = nm_setting_vpn_get_secret(s_vpn, NM_IPOP_KEY_XMPP_PASSWORD);
    if (value && strlen(value)) {
        json_builder_set_member_name(json_builder, XMPP_PASSWORD_TAG);
        json_builder_add_string_value(json_builder, value);
    }

    value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_IP4_ADDRESS);
    if (value && strlen(value)) {
        json_builder_set_member_name(json_builder, IP4_ADDRESS_TAG);
        json_builder_add_string_value(json_builder, value);
    }

    value = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_IP4_NETMASK);
    if (value && strlen(value)) {
        if (value && !strncmp(value, "255.", 4)) {
            struct in_addr addr;
            if (inet_pton(AF_INET, value, &addr) == 1) {
                netmask = nm_utils_ip4_netmask_to_prefix(addr.s_addr);
                json_builder_set_member_name(json_builder, IP4_NETMASK_TAG);
                json_builder_add_int_value(json_builder, netmask);
            }
        } else {
            errno = 0;
            netmask = strtol(value, NULL, 10);
            if (errno == 0) {
                json_builder_set_member_name(json_builder, IP4_NETMASK_TAG);
                json_builder_add_int_value(json_builder, netmask);
            }
        }
    }

    json_builder_end_object(json_builder);
    json_generator = json_generator_new();
    json_generator_set_pretty(json_generator, TRUE);
    json_generator_set_indent(json_generator, 4);
    json_generator_set_indent_char(json_generator, ' ');
    json_root = json_builder_get_root(json_builder);
    json_generator_set_root(json_generator, json_root);
    success = json_generator_to_file(json_generator, path, NULL);

    json_node_free(json_root);
    g_object_unref(json_generator);
    g_object_unref(json_builder);

	return success;
}

