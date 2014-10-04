/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ipop-service - ipop integration with NetworkManager
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2010 Dan Williams <dcbw@redhat.com>
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
 * $Id: nm-ipop-service.c 4232 2008-10-29 09:13:40Z tambeti $
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <glib/gprintf.h>
#include <json-glib/json-glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include <nm-setting-vpn.h>

#include "nm-ipop-service.h"
#include "nm-utils.h"
#include "common/utils.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;
static GMainLoop *loop = NULL;

G_DEFINE_TYPE(NMIPOPPlugin, nm_ipop_plugin, NM_TYPE_VPN_PLUGIN)

#define NM_IPOP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IPOP_PLUGIN, NMIPOPPluginPrivate))

#define NM_IPOP_SVPN_MAX_CONNECT_COUNT 30

/**
 * data needed to setup connection via svpn_controller.py
 */
typedef struct {
    char* ip4;
    char* ip6;
} NMIPOPPluginIOData;

/**
 * plugin data used to handle ipop/svpn_controller processes
 */
typedef struct {
    GPid ipop_pid;
    GPid svpn_pid;
    //GIOChannel* svpn_socket_channel;
    //guint svpn_socket_channel_eventid;
    guint connect_timer;
    guint connect_count;
    NMIPOPPluginIOData *io_data;
} NMIPOPPluginPrivate;

/**
 * features a property has to fullfill
 */
typedef struct {
    const char *name;
    GType type;
    gint int_min;
    gint int_max;
    gboolean address;
} ValidProperty;

/**
 * nm service properties and their features
 *
 * "-flags" marks the state
 * possible values are NMSettingSecretFlags from libnm-util/nm-setting.h
 *  - NM_SETTING_SECRET_FLAG_NONE
 *  - NM_SETTING_SECRET_FLAG_AGENT_OWNED
 *  - NM_SETTING_SECRET_FLAG_NOT_SAVED
 *  - NM_SETTING_SECRET_FLAG_NOT_REQUIRED
 *
 * ip4 netmask could be given as address or prefix
 */
static ValidProperty valid_properties[] = {
    {NM_IPOP_KEY_IP4_ADDRESS,           G_TYPE_STRING,  0,  0,  TRUE},
    {NM_IPOP_KEY_IP4_NETMASK,           G_TYPE_STRING,  0,  0,  TRUE},
    {NM_IPOP_KEY_XMPP_HOST,             G_TYPE_STRING,  0,  0,  TRUE},
    {NM_IPOP_KEY_XMPP_USERNAME,         G_TYPE_STRING,  0,  0,  FALSE},
    {NM_IPOP_KEY_XMPP_PASSWORD"-flags", G_TYPE_STRING,  0,  0,  FALSE},
    {NULL,                              G_TYPE_NONE,    0,  0,  FALSE}
};

/**
 * nm service secrets and their features
 */
static ValidProperty valid_secrets[] = {
    {NM_IPOP_KEY_XMPP_PASSWORD,         G_TYPE_STRING,  0,  0,  FALSE},
    {NULL,                              G_TYPE_NONE,    0,  0,  FALSE}
};

/**
 * data about the validation of a given property
 */
typedef struct ValidateInfo {
    ValidProperty *table;
    GError **error;
    gboolean have_items;
} ValidateInfo;

/**
 * @brief validate_address
 * @param address
 * @return boolean
 */
static gboolean validate_address(const char *address) {
	const char *p = address;

	if (!address || !strlen (address))
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

/**
 * @brief validate_one_property
 * @param key
 * @param value
 * @param user_data
 */
static void validate_one_property(const char *key, const char *value, gpointer user_data) {
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (!prop.address || validate_address (value))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid address '%s'"),
			             key);
			break;
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop.int_min && tmp <= prop.int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property '%s' or out of range [%d -> %d]"),
			             key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             /* Translators: keep "yes" and "no" untranslated! */
			             _("invalid boolean property '%s' (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property '%s' type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property '%s' invalid or not supported"),
		             key);
	}
}

/**
 * @brief nm_ipop_validate_properties
 * @param s_vpn
 * @param error
 * @return boolean
 */
static gboolean nm_ipop_validate_properties(NMSettingVPN *s_vpn, GError **error) {
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_properties[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	if (validate_error) {
		*error = validate_error;
		return FALSE;
	}
	return TRUE;
}

/**
 * @brief nm_ipop_secrets_validate
 * @param s_vpn
 * @param error
 * @return
 */
static gboolean nm_ipop_validate_secrets(NMSettingVPN *s_vpn, GError **error) {
	GError *validate_error = NULL;
    ValidateInfo info = { &valid_secrets[0], &validate_error, FALSE };

    nm_setting_vpn_foreach_secret(s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
	}

	if (validate_error) {
		*error = validate_error;
		return FALSE;
	}
	return TRUE;
}


static char* nm_ipop_svpn_socket_request(NMIPOPPlugin *plugin, GIOChannel* socket_channel, char* request) {
    GString* response;
    gchar* tmp;
    gsize size;
    int i;

    response = g_string_new(NULL);

    // write request to socket channel
    g_io_channel_write_chars(socket_channel, request, strlen(request), NULL, NULL);
    g_io_channel_flush(socket_channel, NULL);

    // wait for first line to read
    g_io_channel_read_line(socket_channel, &tmp, &size, NULL, NULL);
    i = 0;
    while(i < 5 && !tmp && !strlen(tmp)) {
        usleep(200);
        g_io_channel_read_line(socket_channel, &tmp, &size, NULL, NULL);
        i++;
    }
    // exit if threshold reached
    if (i >= 5) return NULL;

    // append lines till "}" reached
    i = 0;
    while(i < 50 && tmp && strlen(tmp) && !g_str_has_prefix(tmp, "}")) {
        // append to string
        g_string_append(response, g_strstrip(tmp));

        g_io_channel_read_line(socket_channel, &tmp, &size, NULL, NULL);
        i++;
    }
    // exit if threshold reached
    if (i >= 50) return NULL;

    // append last line if "}" reached
    if (tmp && strlen(tmp) && g_str_has_prefix(tmp, "}")) {
        g_string_append(response, g_strstrip(tmp));
    }

    if (debug) g_message("response: %s", response->str);
    return response->str;
}

/**
 * @brief send_config_to_nm
 * @param plugin
 * @return
 */
static gboolean send_config_to_nm(NMIPOPPlugin* plugin) {
    NMIPOPPluginPrivate* priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);
    DBusGProxy *proxy;
    DBusGConnection *connection;
    GHashTable *config, *ip4config, *ip6config;
    char *tmp;
    GValue *val;
    GError *err = NULL;

    // really needed?
    g_type_init ();

    // connect to dbus system
    connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
    if (!connection) {
        g_warning ("Could not get the system bus: %s", err->message);
        exit (1);
    }

    // start data tables
    config      = g_hash_table_new(g_str_hash, g_str_equal);
    ip4config   = g_hash_table_new(g_str_hash, g_str_equal);
    ip6config   = g_hash_table_new(g_str_hash, g_str_equal);

    tmp = "ipop"; ///sys/device/virtual/net/ipop";
    val = str_to_gvalue(tmp, FALSE);
    g_hash_table_insert(config, NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
    g_hash_table_insert(config, NM_VPN_PLUGIN_CONFIG_HAS_IP4, bool_to_gvalue (TRUE));
    g_hash_table_insert(config, NM_VPN_PLUGIN_CONFIG_HAS_IP6, bool_to_gvalue (TRUE));

    // Internal VPN subnet gateway
    val = addr_to_gvalue(priv->io_data->ip4);
    if (val)
        g_hash_table_insert(ip4config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);

    val = addr_to_gvalue(priv->io_data->ip6);
    if (val)
        g_hash_table_insert(ip6config, NM_VPN_PLUGIN_IP6_CONFIG_PTP, val);

    // VPN device
    tmp = "/sys/device/virtual/net/ipop";
    g_message("device tmp: %s", tmp);
    val = str_to_gvalue (tmp, FALSE);
    if (val)
        g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);

    // IP address
    val = addr_to_gvalue(priv->io_data->ip4);
    if (val)
        g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
    val = addr_to_gvalue(priv->io_data->ip6);
    if (val)
        g_hash_table_insert (ip6config, NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, val);

    /* TODO: gather further informations about connection
    // netmask (with conversion if given as address)
    tmp = "255.255.255.0";
    val = g_slice_new0(GValue);
    g_value_init(val, G_TYPE_UINT);
    if (tmp && !strncmp (tmp, "255.", 4)) {
        guint32 addr;
        addr = g_value_get_uint(val);
        g_value_set_uint(val, nm_utils_ip4_netmask_to_prefix(addr));
    } else {
        g_value_set_uint(val, 24);
    }
    g_hash_table_insert(ip4config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);*/

    // prevent from getting default route
    g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, bool_to_gvalue (TRUE));

    // setup dbus proxy
    proxy = dbus_g_proxy_new_for_name (connection,
                                NM_DBUS_SERVICE_IPOP,
                                NM_VPN_DBUS_PLUGIN_PATH,
                                NM_VPN_DBUS_PLUGIN_INTERFACE);

    // send "normal" config
    dbus_g_proxy_call_no_reply (proxy, "SetConfig",
                    dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
                    config,
                    G_TYPE_INVALID,
                    G_TYPE_INVALID);

    // send ip4 config
    dbus_g_proxy_call_no_reply (proxy, "SetIp4Config",
                    dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
                    ip4config,
                    G_TYPE_INVALID,
                    G_TYPE_INVALID);

    // send ip6 config
    dbus_g_proxy_call_no_reply (proxy, "SetIp6Config",
                    dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
                    ip6config,
                    G_TYPE_INVALID,
                    G_TYPE_INVALID);

    g_object_unref (proxy);

    return TRUE;
}

static gboolean nm_ipop_connect_timer_cb(gpointer data) {
    NMIPOPPlugin *plugin = NM_IPOP_PLUGIN(data);
    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);

    struct sockaddr_in     serv_addr;
    gint                   socket_fd = -1;

    // setup io channel to svpn_controller on 127.0.0.1:5800
    // needed to get information about connection

    // one way to get socket paket data from installed ipoplib.py
    //python -c "import imp; ipoplib = imp.load_source('ipoplib', '/usr/sbin/ipop/ipoplib.py'); print ipoplib.ipop_ver+ipoplib.tincan_control"

    // increase connection counter (stop if failed NM_IPOP_SVPN_MAX_CONNECT_COUNT times)
    priv->connect_count++;

    // open socket and start listener
    socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        priv->connect_timer = 0;
        return FALSE;
    }

    // set ip and port
    serv_addr.sin_family = AF_INET;
    if (inet_pton (AF_INET, "127.0.0.1", &(serv_addr.sin_addr)) <= 0)
        g_warning ("%s: could not convert 127.0.0.1", __func__);
    serv_addr.sin_port = htons(5800);

    // connect socket; handle failure
    if (!(connect(socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0)) {
        close(socket_fd);

        // try again if NM_IPOP_SVPN_MAX_CONNECT_COUNT not exceeded
        if (priv->connect_count <= NM_IPOP_SVPN_MAX_CONNECT_COUNT)
            return TRUE;

        g_warning("Could not open management socket");
        nm_vpn_plugin_failure(NM_VPN_PLUGIN(plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
        nm_vpn_plugin_set_state(NM_VPN_PLUGIN(plugin), NM_VPN_SERVICE_STATE_STOPPED);

        // end timeout
        priv->connect_timer = 0;
        return FALSE;
    }
    else {
        GIOChannel *svpn_socket_channel;
        JsonParser* json_parser;
        JsonReader* json_reader;
        char* request;
        gchar* response;
        GError* error = NULL;;

        // setup io channel on socket
        svpn_socket_channel = g_io_channel_unix_new(socket_fd);
        g_io_channel_set_encoding(svpn_socket_channel, NULL, NULL);
        //priv->svpn_socket_channel = ipop_svpn_socket_channel;

        // send request and get response
        request = "\x02\x01{\"m\":\"get_state\"}";
        response = nm_ipop_svpn_socket_request(plugin, svpn_socket_channel, request);
        // exit if no response
        if (!response || !strlen(response)) {
            g_warning("No response from svpn socket.");
            nm_vpn_plugin_failure(NM_VPN_PLUGIN(plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
            nm_vpn_plugin_set_state(NM_VPN_PLUGIN(plugin), NM_VPN_SERVICE_STATE_STOPPED);

            // end timeout
            priv->connect_timer = 0;
            return FALSE;
        }
        // remove code from beginning of response
        response = g_strstrip(g_strdelimit(response, "\x02\x01", ' '));

        // parse json response and save information
        json_parser = json_parser_new();
        if (json_parser_load_from_data(json_parser, response, strlen(response), &error)) {
            json_reader = json_reader_new(json_parser_get_root(json_parser));

            if(!json_reader_read_member(json_reader, "_ip4")) {
                g_warning("Could not read IP4 address, error: %s", json_reader_get_error(json_reader)->message);
                nm_vpn_plugin_failure(NM_VPN_PLUGIN(plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
                nm_vpn_plugin_set_state(NM_VPN_PLUGIN(plugin), NM_VPN_SERVICE_STATE_STOPPED);

                // end timeout
                priv->connect_timer = 0;
                return FALSE;
            }
            priv->io_data->ip4 = g_strdup(json_reader_get_string_value(json_reader));
            json_reader_end_member(json_reader);

            if(!json_reader_read_member(json_reader, "_ip6")) {
                g_warning("Could not read IP6 address, error: %s", json_reader_get_error(json_reader)->message);
                nm_vpn_plugin_failure(NM_VPN_PLUGIN(plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
                nm_vpn_plugin_set_state(NM_VPN_PLUGIN(plugin), NM_VPN_SERVICE_STATE_STOPPED);

                // end timeout
                priv->connect_timer = 0;
                return FALSE;
            }
            priv->io_data->ip6 = g_strdup(json_reader_get_string_value(json_reader));
            json_reader_end_member(json_reader);
        } else {
            g_warning("Could not parse svpn result, error: %s", error->message);
            nm_vpn_plugin_failure(NM_VPN_PLUGIN(plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
            nm_vpn_plugin_set_state(NM_VPN_PLUGIN(plugin), NM_VPN_SERVICE_STATE_STOPPED);

            // end timeout
            priv->connect_timer = 0;
            return FALSE;
        }

        // send the config info to networkmanager
        if(send_config_to_nm(plugin)) {
            // end timeout cause we send the information successfully
            priv->connect_timer = 0;
            return FALSE;
        }
    }

    // timeout has to called again cause socket or dbus connection failed
    return TRUE;
}

/**
 * @brief nm_ipop_schedule_connect_timer
 * @detail needed to wait for password to be send to svpn_controller before sending data to nm via dbus
 * @param plugin
 */
static void nm_ipop_schedule_connect_timer(NMIPOPPlugin* plugin){
    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE (plugin);

    if (priv->connect_timer == 0)
        priv->connect_timer = g_timeout_add(200, nm_ipop_connect_timer_cb, plugin);
}

/**
 * @brief ipop_watch_cb
 * @detail watch changes of ipop binary
 * @param pid
 * @param status
 * @param user_data
 */
static void ipop_watch_cb(GPid pid, gint status, gpointer user_data){
    NMVPNPlugin *plugin = NM_VPN_PLUGIN(user_data);
    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);
	NMVPNPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	guint error = 0;
	gboolean good_exit = FALSE;

    if (WIFEXITED(status)) {
        error = WEXITSTATUS(status);
		if (error != 0)
            g_warning("ipop exited with error code %d", error);
    }
    else if (WIFSTOPPED(status))
        g_warning("ipop stopped unexpectedly with signal %d", WSTOPSIG(status));
    else if (WIFSIGNALED(status))
        g_warning("ipop died with signal %d", WTERMSIG(status));
	else
        g_warning("ipop died from an unknown cause");
  
	/* Reap child if needed. */
    waitpid(priv->ipop_pid, NULL, WNOHANG);
    priv->ipop_pid = 0;

	/* IPOP doesn't supply useful exit codes :( */
    switch(error) {
	case 0:
		good_exit = TRUE;
		break;
	default:
		failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
		break;
	}

	if (!good_exit)
        nm_vpn_plugin_failure(plugin, failure);

    nm_vpn_plugin_set_state(plugin, NM_VPN_SERVICE_STATE_STOPPED);
}

static void svpn_watch_cb(GPid pid, gint status, gpointer user_data){
    NMVPNPlugin *plugin = NM_VPN_PLUGIN(user_data);
    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);
    NMVPNPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
    guint error = 0;
    gboolean good_exit = FALSE;

    if (WIFEXITED(status)) {
        error = WEXITSTATUS(status);
        if (error != 0)
            g_warning ("svpn exited with error code %d", error);
    }
    else if (WIFSTOPPED(status))
        g_warning("svpn stopped unexpectedly with signal %d", WSTOPSIG(status));
    else if (WIFSIGNALED(status))
        g_warning("svpn died with signal %d", WTERMSIG(status));
    else
        g_warning("svpn died from an unknown cause");

    /* Reap child if needed. */
    waitpid(priv->svpn_pid, NULL, WNOHANG);
    priv->svpn_pid = 0;

    g_message("svpn stopped with code %d.", error);

    /* handle error code */
    switch (error) {
    case 0:
        good_exit = TRUE;
        break;
    default:
        failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
        break;
    }

    if (!good_exit)
        nm_vpn_plugin_failure(plugin, failure);

    nm_vpn_plugin_set_state(plugin, NM_VPN_SERVICE_STATE_STOPPED);
}

/**
 * @brief nm_ipop_start_ipop_binary
 * @detail starts ipop binary needed for svpn controller
 * @param error
 * @return
 */
static gboolean nm_ipop_start_ipop_binary(NMIPOPPlugin* plugin, GError** error) {
    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);
    const char* ipop_binary;
    GPtrArray *kill_args, *args;
    GPid pid;
    GSource* ipop_watch;
    gchar **stderr, **stdout;
    const char *ipop_binary_paths[] = {
        "/usr/sbin/ipop/ipop-tincan",
        //"/sbin/ipop",
        //"/usr/local/sbin/ipop",
        NULL
    };

    /* Find ipop */
    ipop_binary = find_file(ipop_binary_paths);
    if (!ipop_binary) {
        g_set_error(error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                     "%s",
                     _("Could not find the ipop binary."));
        return FALSE;
    }

    /* Kill old ipop binaries, is that realy necessary??? */
    kill_args = g_ptr_array_new();
    nm_ipop_add_arg(kill_args, "killall");
    nm_ipop_add_arg(kill_args, ipop_binary);
    g_ptr_array_add(kill_args, NULL);
    stdout = NULL;
    stderr = NULL;
    if (!g_spawn_sync(NULL, (char**)kill_args->pdata, NULL,
                        G_SPAWN_SEARCH_PATH, NULL, NULL, stdout, stderr, NULL, error)) {
        nm_ipop_free_args(kill_args);
        g_message("Could not kill ipop-tincan processes; out:%s, err:%s, error:%s", *stdout, *stderr, (*error)->message);
        return FALSE;
    }
    nm_ipop_free_args(kill_args);

    /* Start ipop binary */
    args = g_ptr_array_new();
    nm_ipop_add_arg(args, ipop_binary);
    g_ptr_array_add(args, NULL);

    if (!g_spawn_async(NULL, (char **)args->pdata, NULL,
                        G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
        nm_ipop_free_args(args);
        return FALSE;
    }
    nm_ipop_free_args(args);

    g_message("ipop started with pid %d", pid);

    priv->ipop_pid = pid;
    ipop_watch = g_child_watch_source_new(pid);
    g_source_set_callback(ipop_watch, (GSourceFunc)ipop_watch_cb, plugin, NULL);
    g_source_attach(ipop_watch, NULL);
    g_source_unref(ipop_watch);

    return TRUE;
}

/**
 * @brief nm_ipop_start_svpn_binary
 * @detail starts svpn_controller with pipes to send password later
 * @param plugin
 * @param s_vpn
 * @param error
 * @return
 */
static gboolean nm_ipop_start_svpn_controller(NMIPOPPlugin* plugin,
                                 NMSettingVPN* s_vpn,
                                 GError** error) {
    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE (plugin);
    const char *svpn_binary, *tmp, *password;
    gchar* string;
    GPtrArray* args;
    JsonBuilder* json_builder;
    JsonGenerator* json_generator;
    JsonNode* json_root;
    GSource* svpn_watch;
    GPid pid;
    gint in, out;
    GIOChannel *in_ch, *out_ch;
    gsize size;
    int i, netmask;
    const char *svpn_binary_paths[] = {
        "/usr/sbin/ipop/svpn_controller.py",
        //"/sbin/svpn_controller.py",
        //"/usr/local/sbin/svpn_controller.py",
        NULL
    };

    /* Find svpn binary */
    svpn_binary = find_file(svpn_binary_paths);
    if (!svpn_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
                     _("Could not find the svpn binary."));
		return FALSE;
    }

    args = g_ptr_array_new();
    nm_ipop_add_arg(args, svpn_binary);

    // controller should use stdout to ask for password
    nm_ipop_add_arg(args, "--pwdstdout");

    // other parameters have to be part of a json formatted string
    json_builder = json_builder_new();
    json_builder_begin_object(json_builder);

    tmp = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_HOST);
    if (tmp && strlen(tmp)) {
        //nm_ipop_add_optional_arg(args, "--host", tmp);
        json_builder_set_member_name(json_builder, "xmpp_host");
        json_builder_add_string_value(json_builder, tmp);
    }

    tmp = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_USERNAME);
    if (tmp && strlen(tmp)) {
        //nm_ipop_add_optional_arg(args, "--username", tmp);
        json_builder_set_member_name(json_builder, "xmpp_username");
        json_builder_add_string_value(json_builder, tmp);
    }

    tmp = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_IP4_ADDRESS);
    if (tmp && strlen(tmp)) {
        //nm_ipop_add_optional_arg(args, "--ip4address", tmp);
        json_builder_set_member_name(json_builder, "ip4");
        json_builder_add_string_value(json_builder, tmp);
    }

    tmp = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_IP4_NETMASK);
    if (tmp && strlen(tmp)) {
        if (tmp && !strncmp(tmp, "255.", 4)) {
            struct in_addr addr;
            if (inet_pton(AF_INET, tmp, &addr) == 1) {
                netmask = nm_utils_ip4_netmask_to_prefix(addr.s_addr);
                json_builder_set_member_name(json_builder, "ip4_mask");
                json_builder_add_int_value(json_builder, netmask);
            }
        } else {
            errno = 0;
            netmask = strtol(tmp, NULL, 10);
            if (errno == 0) {
                //nm_ipop_add_optional_arg(args, "--ip4netmask", tmp);
                json_builder_set_member_name(json_builder, "ip4_mask");
                json_builder_add_int_value(json_builder, netmask);
            }
        }
    }

    json_builder_end_object(json_builder);
    json_generator = json_generator_new();
    json_root = json_builder_get_root(json_builder);
    json_generator_set_root(json_generator, json_root);
    string = json_generator_to_data(json_generator, NULL);
    if(debug) g_message("generated json parameter string: %s", string);

    json_node_free(json_root);
    g_object_unref(json_generator);
    g_object_unref(json_builder);

    nm_ipop_add_optional_arg(args, "-s", string);

    // password will be needed later when svpn_controller will ask for it
    password = nm_setting_vpn_get_secret(s_vpn, NM_IPOP_KEY_XMPP_PASSWORD);
    if (password && strlen(password)) {
        password = g_strdup_printf("%s\n", password);
    }
    else {
        /* No password specified? Exit! */
        g_set_error (
            error,
            NM_VPN_PLUGIN_ERROR,
            NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
            "%s",
            _("No password specified."));
        nm_ipop_free_args(args);

        // write zeros over password memory space
        memset((void*)password, 0, strlen(password));

        return FALSE;
    }

    // finalize arguments by a NULL
    g_ptr_array_add(args, NULL);

    if(debug) {
        g_message("svpn args:");

        for (i = 0; i < args->len; ++i) {
            g_message("%d: %s",i,(char *)args->pdata[i]);
        }
    }

    // run svpn_controller with pipes
    if (!g_spawn_async_with_pipes(NULL, (char **)args->pdata, NULL,
                        G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &in, &out, NULL, error)) {
        nm_ipop_free_args(args);
        return FALSE;
    }
    nm_ipop_free_args(args);

    if(debug) g_message("svpn started with pid %d", pid);

    // add io channels for stdin and stdout
    in_ch = g_io_channel_unix_new(in);
    out_ch = g_io_channel_unix_new(out);

    // wait till svpn asks for password and simply write password to in channel
    g_io_channel_read_line(out_ch, &string, &size, NULL, NULL);
    i = 0;
    while(i < 30 && !string && !strlen(string) && !(g_str_has_prefix(string, "Password"))) {
        usleep(200);
        g_io_channel_read_line(out_ch, &string, &size, NULL, NULL);
        i++;
    }

    // reached threshold?
    if (i >= 30) {
        g_set_error (
            error,
            NM_VPN_PLUGIN_ERROR,
            NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
            "%s",
            _("Svpn controller didn't ask for password."));
        nm_ipop_free_args(args);

        // write zeros over password memory space
        memset((void*)password, 0, strlen(password));

        // free channels
        g_io_channel_unref(in_ch);
        g_io_channel_unref(out_ch);

        return FALSE;
    }

    // write password
    g_io_channel_write_chars(in_ch, password, strlen(password), NULL, NULL);
    g_io_channel_flush(in_ch, NULL);

    // write zeros over password memory space
    memset((void*)password, 0, strlen(password));

    // free channels
    g_io_channel_unref(in_ch);
    g_io_channel_unref(out_ch);

    // add callback function to watch for death of svpn_controller
    priv->svpn_pid = pid;
    svpn_watch = g_child_watch_source_new(pid);
    g_source_set_callback(svpn_watch, (GSourceFunc)svpn_watch_cb, plugin, NULL);
    g_source_attach(svpn_watch, NULL);
    g_source_unref(svpn_watch);

    nm_ipop_schedule_connect_timer(plugin);

	return TRUE;
}

/**
 * @brief real_connect
 * @detail gets vpn settings and starts vpn binary
 * @param plugin
 * @param connection
 * @param error
 * @return
 */
static gboolean real_connect(NMVPNPlugin* plugin,
              NMConnection* connection,
              GError** error) {

    NMSettingVPN* s_vpn;

    /* get vpn settings for connection */
    s_vpn = NM_SETTING_VPN(nm_connection_get_setting(connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
        g_set_error(error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	/* Need a username for any password-based connection types */
    if (!nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_HOST) ||
        !nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_USERNAME)) {
        g_set_error(error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
                     "%s",
                     _("Could not process the request because no xmpp host or username was provided."));
        return FALSE;
    }

	/* Validate the properties */
    if (!nm_ipop_validate_properties(s_vpn, error))
		return FALSE;

    /* Validate secrets */
    if (!nm_ipop_validate_secrets(s_vpn, error))
        return FALSE;

    nm_vpn_plugin_set_state(plugin, NM_VPN_SERVICE_STATE_STARTING);

    /* Start IPOP device */
    if (!nm_ipop_start_ipop_binary(NM_IPOP_PLUGIN(plugin), error))
        return FALSE;

    /* Finally try to start svpn controller */
    if (!nm_ipop_start_svpn_controller(NM_IPOP_PLUGIN(plugin), s_vpn, error))
		return FALSE;

    nm_vpn_plugin_set_state(plugin, NM_VPN_SERVICE_STATE_STARTED);

	return TRUE;
}

/**
 * @brief real_need_secrets
 * @detail check if plugin needs secrets
 * @param plugin
 * @param connection
 * @param setting_name
 * @param error
 * @return
 */
static gboolean real_need_secrets(NMVPNPlugin *plugin, NMConnection *connection,
                                    char **setting_name, GError **error) {
    //NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE (plugin);
    NMSettingVPN *s_vpn;
    gboolean need_secrets = TRUE;
    NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (debug) {
		g_message ("%s: connection -------------------------------------", __func__);
		nm_connection_dump (connection);
	}

    s_vpn = NM_SETTING_VPN(nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

    /* Password auth */
    nm_setting_get_secret_flags(NM_SETTING(s_vpn), NM_IPOP_KEY_XMPP_PASSWORD, &flags, NULL);
    switch(flags) {
        // flag not set -> act like agent_owned
        case NM_SETTING_SECRET_FLAG_NONE:

        // password is saved -> retrieve it
        case NM_SETTING_SECRET_FLAG_AGENT_OWNED:
            if (nm_setting_vpn_get_secret(NM_SETTING_VPN (s_vpn), NM_IPOP_KEY_XMPP_PASSWORD)) {
                need_secrets = FALSE;
                //priv->io_data->xmpp_password_send = FALSE;
            }
            break;

        // password not saved but required -> ask for it
        case NM_SETTING_SECRET_FLAG_NOT_SAVED:
            need_secrets = TRUE;
            //priv->io_data->xmpp_password_send = FALSE;
            break;

        // password not required -> do nothing (and we don't have to send anything -> send flag = TRUE)
        case NM_SETTING_SECRET_FLAG_NOT_REQUIRED:
            //priv->io_data->xmpp_password_send = TRUE;
            break;
    }

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

    g_message("setting name: %s", *setting_name);

	return need_secrets;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

/**
 * @brief real_disconnect
 * @detail disconnect svpn and ipop
 * @param plugin
 * @param err
 * @return
 */
static gboolean real_disconnect(NMVPNPlugin* plugin, GError** err) {
	NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE (plugin);

    if (priv->svpn_pid) {
        //// free io channels
        //g_io_channel_unref(priv->svpn_in_channel);
        //g_io_channel_unref(priv->svpn_out_channel);

        if (kill(priv->svpn_pid, SIGTERM) == 0)
            g_timeout_add(2000, ensure_killed, GINT_TO_POINTER(priv->svpn_pid));
		else
            kill(priv->svpn_pid, SIGKILL);

        g_message("Terminated svpn with PID %d.", priv->svpn_pid);
        priv->svpn_pid = 0;
	}

    g_message("disconnecting and ipop_pid is %d.", priv->ipop_pid);
    if (priv->ipop_pid) {
        if (kill(priv->ipop_pid, SIGTERM) == 0)
            g_timeout_add(2000, ensure_killed, GINT_TO_POINTER(priv->ipop_pid));
        else
            kill(priv->ipop_pid, SIGKILL);

        g_message("Terminated ipop with PID %d.", priv->ipop_pid);
        priv->ipop_pid = 0;
    }

	return TRUE;
}

/**
 * @brief nm_ipop_plugin_init
 * @param plugin
 */
static void nm_ipop_plugin_init(NMIPOPPlugin* plugin) {
}

/**
 * @brief nm_ipop_plugin_class_init
 * @detail inits plugin class, connects methods
 * @param plugin_class
 */
static void nm_ipop_plugin_class_init(NMIPOPPluginClass* plugin_class) {
    GObjectClass* object_class = G_OBJECT_CLASS(plugin_class);
    NMVPNPluginClass* parent_class = NM_VPN_PLUGIN_CLASS(plugin_class);

    g_type_class_add_private(object_class, sizeof(NMIPOPPluginPrivate));

    /* virtual methods */
    parent_class->connect      = real_connect;
    parent_class->need_secrets = real_need_secrets;
    parent_class->disconnect   = real_disconnect;
}


/**
 * @brief plugin_state_changed
 * @detail resets the connection timer and disconnects the management socket
 * @param plugin
 * @param state
 * @param user_data
 */
static void plugin_state_changed(NMIPOPPlugin* plugin,
                      NMVPNServiceState state,
                      gpointer user_data) {

    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);

    switch(state) {
    case NM_VPN_SERVICE_STATE_UNKNOWN:
        g_message("state: %d (unknown)", state);
        break;
    case NM_VPN_SERVICE_STATE_INIT:
        g_message("state: %d (init)", state);
        break;
    case NM_VPN_SERVICE_STATE_STARTING:
        g_message("state: %d (starting)", state);
        break;
    case NM_VPN_SERVICE_STATE_STARTED:
        g_message("state: %d (started)", state);
        break;
    case NM_VPN_SERVICE_STATE_SHUTDOWN:
        g_message("state: %d (shutdown)", state);
        break;
    case NM_VPN_SERVICE_STATE_STOPPING:
        g_message("state: %d (stopping)", state);
        break;
    case NM_VPN_SERVICE_STATE_STOPPED:
        g_message("state: %d (stopped)", state);
        break;
    default:
        g_message("state: %d (?)", state);
        break;
    }

    switch(state) {
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
		/* Cleanup on failure */
		if (priv->connect_timer) {
            g_source_remove(priv->connect_timer);
			priv->connect_timer = 0;
		}
        //nm_ipop_disconnect_management_socket(plugin);
		break;
	default:
		break;
	}
}

/**
 * @brief nm_ipop_plugin_new
 * @detail creates a new plugin object and connects the state-changed callback (plugin_state_changed)
 * @return NMIPOPPlugin*
 */
NMIPOPPlugin* nm_ipop_plugin_new(void) {
    NMIPOPPlugin* plugin;
    NMIPOPPluginPrivate* priv;

    plugin =  (NMIPOPPlugin*) g_object_new(NM_TYPE_IPOP_PLUGIN,
                                            NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
                                            NM_DBUS_SERVICE_IPOP,
                                            NULL);

    if (plugin) {
        g_signal_connect(G_OBJECT(plugin), "state-changed", G_CALLBACK(plugin_state_changed), NULL);

        priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);
        // setup io data memory space
        priv->io_data = g_malloc0 (sizeof (NMIPOPPluginIOData));
    }

	return plugin;
}

/**
 * @brief signal_handler
 * @detail quits the GMainLoop, if SIGINT or SIGTERM send
 * @param signo
 */
static void signal_handler(int signo) {
	if (signo == SIGINT || signo == SIGTERM)
        g_main_loop_quit(loop);
}

/**
 * @brief setup_signals
 * @detail creates a signal handler for SIGTERM and SIGINT
 */
static void setup_signals(void) {
	struct sigaction action;
	sigset_t mask;

    sigemptyset(&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
    sigaction(SIGTERM,  &action, NULL);
    sigaction(SIGINT,  &action, NULL);
}

/**
 * @brief quit_mainloop
 * @detail stops the GMainLoop
 * @param plugin
 * @param user_data
 */
static void quit_mainloop(NMVPNPlugin* plugin, gpointer user_data) {
    g_main_loop_quit((GMainLoop*) user_data);
}

/**
 * @brief handle_options
 * @details holds all option interactions
 * @param argc
 * @param argv
 * @return gboolean persist
 */
gboolean handle_options(int argc, char* argv[]) {
    GOptionContext* opt_ctx = NULL;
    gboolean persist = FALSE;

    GOptionEntry options[] = {
        { "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
        { "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
        {NULL}
    };

    /* Parse options */
    opt_ctx = g_option_context_new("");
    g_option_context_set_translation_domain(opt_ctx, "UTF-8");
    g_option_context_set_ignore_unknown_options(opt_ctx, FALSE);
    g_option_context_set_help_enabled(opt_ctx, TRUE);
    g_option_context_add_main_entries(opt_ctx, options, NULL);

    g_option_context_set_summary(opt_ctx,
        _("nm-vpnc-service provides integrated IPOP capability to NetworkManager."));

    g_option_context_parse(opt_ctx, &argc, &argv, NULL);
    g_option_context_free(opt_ctx);

    if (getenv("IPOP_DEBUG"))
        debug = TRUE;
    if (debug)
        g_message("nm-ipop-service (version " DIST_VERSION ") starting...");

    return persist;
}

/**
 * @brief main
 * @detail handles options, creates plugin, connects signals, runs main loop
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char* argv[]) {
    NMIPOPPlugin* plugin;
    gboolean persist = FALSE;

    // init glib type system
    g_type_init();

    // handle options and get persist
    persist = handle_options(argc, argv);

    // load tun driver
    if (system ("/sbin/modprobe tun") == -1)
        exit(EXIT_FAILURE);

    // create plugin
    plugin = nm_ipop_plugin_new();
	if (!plugin)
        exit(EXIT_FAILURE);

    // create main loop
    loop = g_main_loop_new(NULL, FALSE);

    // connect signals
    if (!persist)
        g_signal_connect(plugin, "quit", G_CALLBACK(quit_mainloop), loop);

    setup_signals();

    // run main loop
    g_main_loop_run(loop);

    // clean up
    g_main_loop_unref(loop);
    g_object_unref(plugin);

    exit(EXIT_SUCCESS);
}
