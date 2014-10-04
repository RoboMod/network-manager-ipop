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

#ifndef KNM_IPOP_SERVICE_H
#define KNM_IPOP_SERVICE_H

#define NM_DBUS_SERVICE_IPOP    "org.freedesktop.NetworkManager.ipop"
#define NM_DBUS_INTERFACE_IPOP  "org.freedesktop.NetworkManager.ipop"
#define NM_DBUS_PATH_IPOP       "/org/freedesktop/NetworkManager/ipop"

#define NM_IPOP_KEY_IP4_ADDRESS "ip4-address"
#define NM_IPOP_KEY_IP4_NETMASK "ip4-netmask"
#define NM_IPOP_KEY_XMPP_HOST "xmpp-host"
#define NM_IPOP_KEY_XMPP_USERNAME "xmpp-username"
#define NM_IPOP_KEY_XMPP_PASSWORD "xmpp-password"

#endif /* KNM_IPOP_SERVICE_H */
