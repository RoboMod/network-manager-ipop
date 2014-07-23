/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ipop-service - ipop integration with NetworkManager
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2008 Dan Williams <dcbw@redhat.com>
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

#ifndef NM_IPOP_SERVICE_H
#define NM_IPOP_SERVICE_H

#include <glib.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_IPOP_PLUGIN            (nm_ipop_plugin_get_type ())
#define NM_IPOP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IPOP_PLUGIN, NMIPOPPlugin))
#define NM_IPOP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IPOP_PLUGIN, NMIPOPPluginClass))
#define NM_IS_IPOP_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IPOP_PLUGIN))
#define NM_IS_IPOP_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IPOP_PLUGIN))
#define NM_IPOP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IPOP_PLUGIN, NMIPOPPluginClass))

#define NM_DBUS_SERVICE_IPOP    "org.freedesktop.NetworkManager.ipop"
#define NM_DBUS_INTERFACE_IPOP  "org.freedesktop.NetworkManager.ipop"
#define NM_DBUS_PATH_IPOP       "/org/freedesktop/NetworkManager/ipop"

#define NM_IPOP_KEY_AUTH "auth"
#define NM_IPOP_KEY_CA "ca"
#define NM_IPOP_KEY_CERT "cert"
#define NM_IPOP_KEY_CIPHER "cipher"
#define NM_IPOP_KEY_COMP_LZO "comp-lzo"
#define NM_IPOP_KEY_CONNECTION_TYPE "connection-type"
#define NM_IPOP_KEY_FRAGMENT_SIZE "fragment-size"
#define NM_IPOP_KEY_KEY "key"
#define NM_IPOP_KEY_LOCAL_IP "local-ip" /* ??? */
#define NM_IPOP_KEY_MSSFIX "mssfix"
#define NM_IPOP_KEY_PORT "port"
#define NM_IPOP_KEY_PROTO_TCP "proto-tcp"
#define NM_IPOP_KEY_PROXY_TYPE "proxy-type"
#define NM_IPOP_KEY_PROXY_SERVER "proxy-server"
#define NM_IPOP_KEY_PROXY_PORT "proxy-port"
#define NM_IPOP_KEY_PROXY_RETRY "proxy-retry"
#define NM_IPOP_KEY_HTTP_PROXY_USERNAME "http-proxy-username"
#define NM_IPOP_KEY_REMOTE "remote"
#define NM_IPOP_KEY_REMOTE_RANDOM "remote-random"
#define NM_IPOP_KEY_REMOTE_IP "remote-ip"
#define NM_IPOP_KEY_STATIC_KEY "static-key"
#define NM_IPOP_KEY_STATIC_KEY_DIRECTION "static-key-direction"
#define NM_IPOP_KEY_TA "ta"
#define NM_IPOP_KEY_TA_DIR "ta-dir"
#define NM_IPOP_KEY_TUNNEL_MTU "tunnel-mtu"
#define NM_IPOP_KEY_USERNAME "username"
#define NM_IPOP_KEY_TAP_DEV "tap-dev"
#define NM_IPOP_KEY_TLS_REMOTE "tls-remote"

#define NM_IPOP_KEY_PASSWORD "password"
#define NM_IPOP_KEY_CERTPASS "cert-pass"
#define NM_IPOP_KEY_HTTP_PROXY_PASSWORD "http-proxy-password"
/* Internal auth-dialog -> service token indicating that no secrets are
 * required for the connection.
 */
#define NM_IPOP_KEY_NOSECRET "no-secret"

#define NM_IPOP_KEY_RENEG_SECONDS "reneg-seconds"

#define NM_IPOP_AUTH_NONE "none"
#define NM_IPOP_AUTH_RSA_MD4 "RSA-MD4"
#define NM_IPOP_AUTH_MD5  "MD5"
#define NM_IPOP_AUTH_SHA1 "SHA1"
#define NM_IPOP_AUTH_SHA224 "SHA224"
#define NM_IPOP_AUTH_SHA256 "SHA256"
#define NM_IPOP_AUTH_SHA384 "SHA384"
#define NM_IPOP_AUTH_SHA512 "SHA512"
#define NM_IPOP_AUTH_RIPEMD160 "RIPEMD160"

#define NM_IPOP_CONTYPE_TLS          "tls"
#define NM_IPOP_CONTYPE_STATIC_KEY   "static-key"
#define NM_IPOP_CONTYPE_PASSWORD     "password"
#define NM_IPOP_CONTYPE_PASSWORD_TLS "password-tls"

typedef struct {
	NMVPNPlugin parent;
} NMIPOPPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMIPOPPluginClass;

GType nm_ipop_plugin_get_type (void);

NMIPOPPlugin *nm_ipop_plugin_new (void);

#endif /* NM_IPOP_SERVICE_H */
