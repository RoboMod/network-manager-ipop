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

/**
 * data needed to setup connection via svpn_controller.py
 */
typedef struct {
    char *xmpp_host;
    char *xmpp_username;
    char *xmpp_password;
} NMIPOPPluginIOData;

/**
 * plugin data used to handle ipop/svpn_controller processes
 */
typedef struct {
    GPid ipop_pid;
    GPid svpn_pid;
    GIOChannel* svpn_in_channel;
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
 * "-flags" marks the state
 * possible values are NMSettingSecretFlags from libnm-util/nm-setting.h
 *  - NM_SETTING_SECRET_FLAG_NONE
 *  - NM_SETTING_SECRET_FLAG_AGENT_OWNED
 *  - NM_SETTING_SECRET_FLAG_NOT_SAVED
 *  - NM_SETTING_SECRET_FLAG_NOT_REQUIRED
 */
static ValidProperty valid_properties[] = {
    {NM_IPOP_KEY_LOCAL_IP,                 G_TYPE_STRING,   0,  0,      TRUE},
    {NM_IPOP_KEY_PORT,                     G_TYPE_INT,      1,  65535,  FALSE},
    {NM_IPOP_KEY_XMPP_HOST,                G_TYPE_STRING,   0,  0,      TRUE},
    {NM_IPOP_KEY_XMPP_USERNAME,            G_TYPE_STRING,   0,  0,      FALSE},
    {NM_IPOP_KEY_XMPP_PASSWORD"-flags",    G_TYPE_STRING,   0,  0,      FALSE},
    {NULL,                                 G_TYPE_NONE,     0,  0,      FALSE}
};

/**
 * nm service secrets and their features
 */
static ValidProperty valid_secrets[] = {
    {NM_IPOP_KEY_XMPP_PASSWORD,            G_TYPE_STRING,   0,   0,      FALSE},
    {NULL,                                 G_TYPE_NONE,     0,   0,      FALSE}
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

//static void
//nm_ipop_disconnect_management_socket (NMIPOPPlugin *plugin)
//{
//	NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE (plugin);
//	NMIPOPPluginIOData *io_data = priv->io_data;

//	/* This should not throw a warning since this can happen in
//	   non-password modes */
//	if (!io_data)
//		return;

//	if (io_data->socket_channel_eventid)
//		g_source_remove (io_data->socket_channel_eventid);
//	if (io_data->socket_channel) {
//		g_io_channel_shutdown (io_data->socket_channel, FALSE, NULL);
//		g_io_channel_unref (io_data->socket_channel);
//	}

//	g_free (io_data->username);
//	g_free (io_data->proxy_username);

//	if (io_data->password)
//		memset (io_data->password, 0, strlen (io_data->password));
//	g_free (io_data->password);

//	if (io_data->priv_key_pass)
//		memset (io_data->priv_key_pass, 0, strlen (io_data->priv_key_pass));
//	g_free (io_data->priv_key_pass);

//	if (io_data->proxy_password)
//		memset (io_data->proxy_password, 0, strlen (io_data->proxy_password));
//	g_free (io_data->proxy_password);

//	g_free (priv->io_data);
//	priv->io_data = NULL;
//}

//static char *
//ovpn_quote_string (const char *unquoted)
//{
//	char *quoted = NULL, *q;
//	char *u = (char *) unquoted;

//	g_return_val_if_fail (unquoted != NULL, NULL);

//	/* FIXME: use unpaged memory */
//	quoted = q = g_malloc0 (strlen (unquoted) * 2);
//	while (*u) {
//		/* Escape certain characters */
//		if (*u == ' ' || *u == '\\' || *u == '"')
//			*q++ = '\\';
//		*q++ = *u++;
//	}

//	return quoted;
//}

///* sscanf is evil, and since we can't use glib regexp stuff since it's still
// * too new for some distros, do a simple match here.
// */
//static char *
//get_detail (const char *input, const char *prefix)
//{
//	char *ret = NULL;
//	guint32 i = 0;
//	const char *p, *start;

//	g_return_val_if_fail (prefix != NULL, NULL);

//	if (!g_str_has_prefix (input, prefix))
//		return NULL;

//	/* Grab characters until the next ' */
//	p = start = input + strlen (prefix);
//	while (*p) {
//		if (*p == '\'') {
//			ret = g_malloc0 (i + 1);
//			strncpy (ret, start, i);
//			break;
//		}
//		p++, i++;
//	}

//	return ret;
//}

//static void
//write_user_pass (GIOChannel *channel,
//                 const char *authtype,
//                 const char *user,
//                 const char *pass)
//{
//	char *quser, *qpass, *buf;

//	/* Quote strings passed back to ipop */
//	quser = ovpn_quote_string (user);
//	qpass = ovpn_quote_string (pass);
//	buf = g_strdup_printf ("username \"%s\" \"%s\"\n"
//	                       "password \"%s\" \"%s\"\n",
//	                       authtype, quser,
//	                       authtype, qpass);
//	memset (qpass, 0, strlen (qpass));
//	g_free (qpass);
//	g_free (quser);

//	/* Will always write everything in blocking channels (on success) */
//	g_io_channel_write_chars (channel, buf, strlen (buf), NULL, NULL);
//	g_io_channel_flush (channel, NULL);

//	memset (buf, 0, strlen (buf));
//	g_free (buf);
//}

//static gboolean
//handle_management_socket (NMVPNPlugin *plugin,
//                          GIOChannel *source,
//                          GIOCondition condition,
//                          NMVPNPluginFailure *out_failure)
//{
//	NMIPOPPluginIOData *io_data = NM_IPOP_PLUGIN_GET_PRIVATE (plugin)->io_data;
//	gboolean again = TRUE;
//	char *str = NULL, *auth = NULL, *buf;

//	if (!(condition & G_IO_IN))
//		return TRUE;

//	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
//		return TRUE;

//	if (strlen (str) < 1)
//		goto out;

//	auth = get_detail (str, ">PASSWORD:Need '");
//	if (auth) {
//		if (strcmp (auth, "Auth") == 0) {
//			if (io_data->username != NULL && io_data->password != NULL)
//				write_user_pass (source, auth, io_data->username, io_data->password);
//			else
//				g_warning ("Auth requested but one of username or password is missing");
//		} else if (!strcmp (auth, "Private Key")) {
//			if (io_data->priv_key_pass) {
//				char *qpass;

//				/* Quote strings passed back to ipop */
//				qpass = ovpn_quote_string (io_data->priv_key_pass);
//				buf = g_strdup_printf ("password \"%s\" \"%s\"\n", auth, qpass);
//				memset (qpass, 0, strlen (qpass));
//				g_free (qpass);

//				/* Will always write everything in blocking channels (on success) */
//				g_io_channel_write_chars (source, buf, strlen (buf), NULL, NULL);
//				g_io_channel_flush (source, NULL);
//				g_free (buf);
//			} else
//				g_warning ("Certificate password requested but private key password == NULL");
//		} else if (strcmp (auth, "HTTP Proxy") == 0) {
//			if (io_data->proxy_username != NULL && io_data->proxy_password != NULL)
//				write_user_pass (source, auth, io_data->proxy_username, io_data->proxy_password);
//			else
//				g_warning ("HTTP Proxy auth requested but either proxy username or password is missing");
//		} else {
//			g_warning ("No clue what to send for username/password request for '%s'", auth);
//			if (out_failure)
//				*out_failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
//			again = FALSE;
//		}
//		g_free (auth);
//	}

//	auth = get_detail (str, ">PASSWORD:Verification Failed: '");
//	if (auth) {
//		if (!strcmp (auth, "Auth"))
//			g_warning ("Password verification failed");
//		else if (!strcmp (auth, "Private Key"))
//			g_warning ("Private key verification failed");
//		else
//			g_warning ("Unknown verification failed: %s", auth);

//		g_free (auth);

//		if (out_failure)
//			*out_failure = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
//		again = FALSE;
//	}

//out:
//	g_free (str);
//	return again;
//}

//static gboolean
//nm_ipop_socket_data_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
//{
//	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
//	NMVPNPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;

//	if (!handle_management_socket (plugin, source, condition, &failure)) {
//		nm_vpn_plugin_failure (plugin, failure);
//		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
//		return FALSE;
//	}

//	return TRUE;
//}

/**
 * @brief str_to_gvalue
 * @param str
 * @param try_convert
 * @return
 */
static GValue* str_to_gvalue(const char *str, gboolean try_convert) {
    GValue *val;

    /* Empty */
    if (!str || strlen (str) < 1)
        return NULL;

    if (!g_utf8_validate (str, -1, NULL)) {
        if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
            str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

        if (!str)
            /* Invalid */
            return NULL;
    }
    val = g_slice_new0 (GValue);
    g_value_init (val, G_TYPE_STRING);
    g_value_set_string (val, str);

    return val;
}

/**
 * @brief addr_to_gvalue
 * @param str
 * @return
 */
static GValue* addr_to_gvalue(const char *str) {
    struct in_addr	temp_addr;
    GValue *val;

    /* Empty */
    if (!str || strlen (str) < 1)
        return NULL;

    if (inet_pton (AF_INET, str, &temp_addr) <= 0)
        return NULL;

    val = g_slice_new0 (GValue);
    g_value_init (val, G_TYPE_UINT);
    g_value_set_uint (val, temp_addr.s_addr);

    return val;
}

/**
 * @brief bool_to_gvalue
 * @param b
 * @return
 */
static GValue* bool_to_gvalue(gboolean b) {
    GValue *val;
    val = g_slice_new0 (GValue);
    g_value_init (val, G_TYPE_BOOLEAN);
    g_value_set_boolean (val, b);
    return val;
}

/**
 * @brief send_config_to_nm
 * @param connection
 * @param config
 * @param ip4config
 */
static void send_config_to_nm(DBusGConnection *connection, GHashTable *config, GHashTable *ip4config) {
    DBusGProxy *proxy;

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

    g_object_unref (proxy);
}

static gboolean nm_ipop_connect_timer_cb(gpointer data) {
    //NMIPOPPlugin *plugin = NM_IPOP_PLUGIN(data);
    //NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE (plugin);
    //struct sockaddr_in     serv_addr;
    //gboolean               connected = FALSE;
    //gint                   socket_fd = -1;
    //NMIPOPPluginIOData *io_data = priv->io_data;

    //GPid pid;
    //GPtrArray *controller_args;

//	priv->connect_count++;

    DBusGConnection *connection;
    GHashTable *config, *ip4config;
    char *tmp;
    GValue *val;
    //int i;
    GError *err = NULL;
    //GValue *dns_list = NULL;
    //GValue *nbns_list = NULL;
    //GValue *dns_domain = NULL;
    //struct in_addr temp_addr;
    //gboolean tapdev = FALSE;
    //char **iter;

    g_type_init ();

    connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
    if (!connection) {
        g_warning ("Could not get the system bus: %s", err->message);
        exit (1);
    }

    config = g_hash_table_new (g_str_hash, g_str_equal);
    ip4config = g_hash_table_new (g_str_hash, g_str_equal);

    tmp = "ipop"; ///sys/device/virtual/net/ipop";
    val = str_to_gvalue (tmp, FALSE);
    g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
    g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_HAS_IP4, bool_to_gvalue (TRUE));

    /* External world-visible VPN gateway */
    //val = trusted_remote_to_gvalue ();
    //if (val)
    //    g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY, val);
    //else
    //	helper_failed (connection, "VPN Gateway");

    /* Internal VPN subnet gateway */
    val = addr_to_gvalue ("172.31.0.100"); //getenv ("route_vpn_gateway"));
    if (val)
        g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);

    /* VPN device */
    tmp = "/sys/device/virtual/net/ipop"; //getenv("dev");
    g_message("device tmp: %s", tmp);
    val = str_to_gvalue (tmp, FALSE);
    //if (val)
        g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
    //else
    //    helper_failed (connection, "Tunnel Device");

    //if (strncmp (tmp, "tap", 3) == 0)
    //    tapdev = TRUE;

    /* IP address */
    val = addr_to_gvalue ("172.31.0.100"); //getenv ("ifconfig_local"));
    //if (val)
        g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
    //else
    //	helper_failed (connection, "IP4 Address");

//	/* PTP address; for vpnc PTP address == internal IP4 address */
//	val = addr_to_gvalue (getenv ("ifconfig_remote"));
//	if (val) {
//		/* Sigh.  IPOP added 'topology' stuff in 2.1 that changes the meaning
//		 * of the ifconfig bits without actually telling you what they are
//		 * supposed to mean; basically relying on specific 'ifconfig' behavior.
//		 */
//		tmp = getenv ("ifconfig_remote");
//		if (tmp && !strncmp (tmp, "255.", 4)) {
//			guint32 addr;

//			/* probably a netmask, not a PTP address; topology == subnet */
//			addr = g_value_get_uint (val);
//			g_value_set_uint (val, nm_utils_ip4_netmask_to_prefix (addr));
//			g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
//		} else
//			g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
//	}

//	/* Netmask
//	 *
//	 * Either TAP or TUN modes can have an arbitrary netmask in newer versions
//	 * of ipop, while in older versions only TAP mode would.  So accept a
//	 * netmask if passed, otherwise default to /32 for TUN devices since they
//	 * are usually point-to-point.
//	 */
//	tmp = getenv ("ifconfig_netmask");
//	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
//		val = g_slice_new0 (GValue);
//		g_value_init (val, G_TYPE_UINT);
//		g_value_set_uint (val, nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));
//		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
//	} else if (!tapdev) {
//		if (!g_hash_table_lookup (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX)) {
            val = g_slice_new0 (GValue);
            g_value_init (val, G_TYPE_UINT);
            g_value_set_uint (val, 24);
            g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
//		}
//	} else
//		g_warning ("No IP4 netmask/prefix (missing or invalid 'ifconfig_netmask')");

    //val = get_routes ();
    //if (val)
    //    g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);

//    	/* DNS and WINS servers */
//	for (i = 1; i < 256; i++) {
//		char *env_name;

//		env_name = g_strdup_printf ("foreign_option_%d", i);
//		tmp = getenv (env_name);
//		g_free (env_name);

//		if (!tmp || strlen (tmp) < 1)
//			break;

//		if (!g_str_has_prefix (tmp, "dhcp-option "))
//			continue;

//		tmp += 12; /* strlen ("dhcp-option ") */

//		if (g_str_has_prefix (tmp, "DNS "))
//			dns_list = parse_addr_list (dns_list, tmp + 4);
//		else if (g_str_has_prefix (tmp, "WINS "))
//			nbns_list = parse_addr_list (nbns_list, tmp + 5);
//		else if (g_str_has_prefix (tmp, "DOMAIN ") && !dns_domain)
//			dns_domain = str_to_gvalue (tmp + 7, FALSE);
//	}

//	if (dns_list)
//		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DNS, dns_list);
//	if (nbns_list)
//		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, nbns_list);
//	if (dns_domain)
//		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, dns_domain);

    // prevent from getting default route
    g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, bool_to_gvalue (TRUE));

    /* Send the config info to nm-ipop-service */
    send_config_to_nm(connection, config, ip4config);

    //g_message("connect timer called");

    return FALSE;
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

static gboolean svpn_out_watch_cb(GIOChannel*   channel,
                                  GIOCondition  cond,
                                  gpointer*     data) {
    NMVPNPlugin *plugin = NM_VPN_PLUGIN(data);
    NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE(plugin);
    gchar *string;
    gsize  size;

    //TODO: lookup what G_IO_HUP means
    if( cond == G_IO_HUP )
    {
        g_io_channel_unref( channel );
        return FALSE;
    }

    // read a line
    g_io_channel_read_line(channel, &string, &size, NULL, NULL );

    if (string && strlen(string)) {
        // check if string starts with "Password"
        if(g_str_has_prefix(string, "Password")) {
            // write password to stdin
            g_io_channel_write_chars(priv->svpn_in_channel, priv->io_data->xmpp_password,
                                     strlen(priv->io_data->xmpp_password), NULL, NULL);
        }
    }


    g_free(string);

    return TRUE;
}

/**
 * @brief nm_find_ipop
 * @detail searchs for ipop binary
 * @return
 */
static const char* nm_find_ipop(void) {
	static const char *ipop_binary_paths[] = {
        "/usr/sbin/ipop/ipop-tincan",
		//"/sbin/ipop",
		//"/usr/local/sbin/ipop",
		NULL
	};
	const char  **ipop_binary = ipop_binary_paths;

	while (*ipop_binary != NULL) {
		if (g_file_test (*ipop_binary, G_FILE_TEST_EXISTS))
			break;
		ipop_binary++;
	}

	return *ipop_binary;
}

/**
 * @brief nm_find_svpn
 * @detail searchs for svpn binary
 * @return
 */
static const char* nm_find_svpn(void) {
    static const char *svpn_binary_paths[] = {
        "/usr/sbin/ipop/svpn_controller.py",
        //"/sbin/svpn_controller.py",
        //"/usr/local/sbin/svpn_controller.py",
        NULL
    };
    const char** svpn_binary = svpn_binary_paths;

    while (*svpn_binary != NULL) {
        if (g_file_test(*svpn_binary, G_FILE_TEST_EXISTS))
            break;
        svpn_binary++;
    }

    return *svpn_binary;
}

/**
 * @brief nm_ipop_free_args
 * @param args
 */
static void nm_ipop_free_args(GPtrArray *args) {
    g_ptr_array_foreach(args, (GFunc) g_free, NULL);
    g_ptr_array_free(args, TRUE);
}

/**
 * @brief nm_ipop_add_arg
 * @param args
 * @param arg
 */
static void nm_ipop_add_arg(GPtrArray *args, const char *arg) {
    g_return_if_fail(args != NULL);
    g_return_if_fail(arg != NULL);

    g_ptr_array_add(args, (gpointer)g_strdup(arg));
}

/**
 * @brief nm_ipop_add_optional_arg
 * @param args
 * @param option
 * @param arg
 */
static void nm_ipop_add_optional_arg(GPtrArray *args, const char* option, const char *arg) {
    g_return_if_fail(args != NULL);
    g_return_if_fail(option != NULL);
    g_return_if_fail(arg != NULL);

    g_ptr_array_add(args, (gpointer)g_strdup(option));
    g_ptr_array_add(args, (gpointer)g_strdup(arg));
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

    /* Find ipop */
    ipop_binary = nm_find_ipop();
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
    const char *svpn_binary, *tmp;
    GPtrArray* args;
    GSource* svpn_watch;
	GPid pid;
    gint in, out;
    GIOChannel *in_ch, *out_ch;
    int i;

    // setup io data memory space
    priv->io_data = g_malloc0 (sizeof (NMIPOPPluginIOData));

    /* Find svpn binary */
    svpn_binary = nm_find_svpn();
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

    // configure file as argument, maybe later again
    //nm_ipop_add_optional_arg(args, "-c", "~/Programing/C++/IPOP/config.json");

    tmp = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_HOST);
    if (tmp && strlen(tmp)) {
        nm_ipop_add_optional_arg(args, "--host", tmp);
    }

    tmp = nm_setting_vpn_get_data_item(s_vpn, NM_IPOP_KEY_XMPP_USERNAME);
    if (tmp && strlen(tmp)) {
        nm_ipop_add_optional_arg(args, "--username", tmp);
    }

    g_message("get xmpp password");
    tmp = nm_setting_vpn_get_secret(s_vpn, NM_IPOP_KEY_XMPP_PASSWORD);
    if (tmp && strlen(tmp)) {
        // simple solution: add password to arguments
        //nm_ipop_add_optional_arg(args, "--password", tmp);

        // better solution: save password in io data and write it to
        // stdin pipe when svpn_controller is asking for it
        priv->io_data->xmpp_password = g_strdup(tmp);
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

    // add callback function to watch for death of svpn_controller
    priv->svpn_pid = pid;
    svpn_watch = g_child_watch_source_new(pid);
    g_source_set_callback(svpn_watch, (GSourceFunc)svpn_watch_cb, plugin, NULL);
    g_source_attach(svpn_watch, NULL);
    g_source_unref(svpn_watch);

    // add io channels for stdin and stdout
    in_ch = g_io_channel_unix_new(in);
    out_ch = g_io_channel_unix_new(out);
    // save in channel
    priv->svpn_in_channel = in_ch;
    // and add a callback for svpn_controller stdout
    g_io_add_watch(out_ch, G_IO_IN | G_IO_HUP, (GIOFunc)svpn_out_watch_cb, plugin);

    // run connect scheduler
    // he will manage the communication to send password to svpn_controller
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
static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error) {
    NMSettingVPN *s_vpn;
    gboolean need_secrets = TRUE;
    NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (debug) {
		g_message ("%s: connection -------------------------------------", __func__);
		nm_connection_dump (connection);
	}

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

    //check_need_secrets (s_vpn, &need_secrets);
    /* Password auth */
    g_message("get secret flags");
    nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_IPOP_KEY_XMPP_PASSWORD, &flags, NULL);
    /* If the password is saved and we can retrieve it, it's not required */
    g_message("get secrets to check their existance");
    if (nm_setting_vpn_get_secret (NM_SETTING_VPN (s_vpn), NM_IPOP_KEY_XMPP_PASSWORD)) {
        need_secrets = FALSE;
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
static gboolean
real_disconnect (NMVPNPlugin* plugin, GError** err) {
	NMIPOPPluginPrivate *priv = NM_IPOP_PLUGIN_GET_PRIVATE (plugin);

    if (priv->svpn_pid) {
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

    plugin =  (NMIPOPPlugin*) g_object_new(NM_TYPE_IPOP_PLUGIN,
                                            NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
                                            NM_DBUS_SERVICE_IPOP,
                                            NULL);
	if (plugin)
        g_signal_connect(G_OBJECT(plugin), "state-changed", G_CALLBACK(plugin_state_changed), NULL);

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
