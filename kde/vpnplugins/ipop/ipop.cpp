/* ipop.cpp - import/export ipop connections
 *
 * Copyright 2008 Will Stephenson <wstephenson@kde.org>
 * Copyright 2011-2012 Rajeesh K Nambiar <rajeeshknambiar@gmail.com>
 * Copyright (C) 2014 Andreas Ihrig <mod.andy@gmx.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License or (at your option) version 3 or any later version
 * accepted by the membership of KDE e.V. (or its successor approved
 * by the membership of KDE e.V.), which shall act as a proxy
 * defined in Section 14 of version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ipop.h"

#include <KPluginFactory>
#include <KMessageBox>

#include "qjson/parser.h"
#include "qjson/serializer.h"
#include <netinet/in.h>

#include <nm-setting-ip4-config.h>
#include "nm-utils.h"

#include "ipopwidget.h"
#include "ipopauth.h"

#include "connection.h"
#include <types.h>
#include "nm-ipop-service.h"
#include "settings/vpn.h"
#include "settings/ipv4.h"

#define XMPP_HOST_TAG "xmpp_host"
#define XMPP_USERNAME_TAG "xmpp_username"
#define XMPP_PASSWORD_TAG "xmpp_password"
#define IP4_ADDRESS_TAG "ip4"
#define IP4_NETMASK_TAG "ip4_mask"

K_PLUGIN_FACTORY( IPOPUiPluginFactory, registerPlugin<IPOPUiPlugin>(); )
K_EXPORT_PLUGIN( IPOPUiPluginFactory( "networkmanagement_ipopui", "libknetworkmanager" ) )

IPOPUiPlugin::IPOPUiPlugin(QObject * parent, const QVariantList &)
    : VpnUiPlugin(parent) {}

IPOPUiPlugin::~IPOPUiPlugin() {}

SettingWidget* IPOPUiPlugin::widget(Knm::Connection * connection,
                                    QWidget * parent) {
    IPOPSettingWidget * wid = new IPOPSettingWidget(connection, parent);
    wid->init();
    return wid;
}

SettingWidget* IPOPUiPlugin::askUser(Knm::Connection * connection,
                                     QWidget * parent) {
    return new IPOPAuthWidget(connection, parent);
}

QString IPOPUiPlugin::suggestedFileName(Knm::Connection *connection) const {
    return connection->name() + ".conf";
}

QString IPOPUiPlugin::supportedFileExtensions() const {
    return "*.conf";
}

QVariantList IPOPUiPlugin::importConnectionSettings(const QString &fileName) {
    QFile impFile(fileName);
    if (!impFile.open(QFile::ReadOnly|QFile::Text)) {
        mError = VpnUiPlugin::Error;
        mErrorMessage = i18n("Could not open file");
        return QVariantList();
    }

    QVariantList conSetting;
    QStringMap dataMap;
    QStringMap secretData;

    bool have_pass = false;

    QJson::Parser json_parser;
    bool ok;
    QVariantMap json_result = json_parser.parse(&impFile, &ok).toMap();
    if (!ok) {
        mError = VpnUiPlugin::Error;
        mErrorMessage = i18n("An error occured during parsing");
        return QVariantList();
    }

    if(json_result.contains(XMPP_HOST_TAG)) {
        dataMap.insert(QLatin1String(NM_IPOP_KEY_XMPP_HOST),
                       json_result[XMPP_HOST_TAG].toString());
    }

    if(json_result.contains(XMPP_USERNAME_TAG)) {
        dataMap.insert(QLatin1String(NM_IPOP_KEY_XMPP_USERNAME),
                       json_result[XMPP_USERNAME_TAG].toString());
    }

    if(json_result.contains(XMPP_PASSWORD_TAG)) {
        secretData.insert(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD),
                          json_result[XMPP_PASSWORD_TAG].toString());
        have_pass = true;
    }

    if(json_result.contains(IP4_ADDRESS_TAG)) {
        dataMap.insert(QLatin1String(NM_IPOP_KEY_IP4_ADDRESS),
                       json_result[IP4_ADDRESS_TAG].toString());
    }

    if(json_result.contains(IP4_NETMASK_TAG)) {
        dataMap.insert(QLatin1String(NM_IPOP_KEY_IP4_NETMASK),
                       json_result[IP4_NETMASK_TAG].toString());
    }

    if (have_pass) {
        dataMap.insert(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD"-flags"),
                       QString::number(Knm::Setting::AgentOwned));
    } else  {
        dataMap.insert(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD"-flags"),
                       QString::number(Knm::Setting::NotSaved));
    }

    conSetting << Knm::VpnSetting::variantMapFromStringList(
                      Knm::VpnSetting::stringMapToStringList(dataMap));
    conSetting << Knm::VpnSetting::variantMapFromStringList(
                      Knm::VpnSetting::stringMapToStringList(secretData));
    conSetting << QFileInfo(fileName).completeBaseName(); // Connection name

    return conSetting;
}

bool IPOPUiPlugin::exportConnectionSettings(Knm::Connection * connection,
                                            const QString &fileName) {
    QFile expFile(fileName);
    if (! expFile.open(QIODevice::WriteOnly | QIODevice::Text) ) {
        mError = VpnUiPlugin::Error;
        mErrorMessage = i18n("Could not open file for writing");
        return false;
    }

    QStringMap dataMap;
    QStringMap secretData;

    Knm::VpnSetting * vpnSetting =
        static_cast<Knm::VpnSetting*>(connection->setting(Knm::Setting::Vpn));
    dataMap = vpnSetting->data();
    secretData = vpnSetting->vpnSecrets();

    QVariantMap json_result;

    if (!dataMap[NM_IPOP_KEY_XMPP_HOST].isEmpty()) {
        json_result.insert(XMPP_HOST_TAG, dataMap[NM_IPOP_KEY_XMPP_HOST]);
    }

    if (!dataMap[NM_IPOP_KEY_XMPP_USERNAME].isEmpty()) {
        json_result.insert(XMPP_USERNAME_TAG,
                           dataMap[NM_IPOP_KEY_XMPP_USERNAME]);
    }

    //TODO: fix output of xmpp password to config file
//    if (!secretData.value(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD)).isEmpty()) {
//        json_result.insert(XMPP_PASSWORD_TAG,
//                    secretData.value(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD)));
//    }
//    if (secretData[NM_IPOP_KEY_XMPP_PASSWORD"-flags"]  == QString::number(Knm::Setting::AgentOwned)) {
//        json_result.insert(XMPP_PASSWORD_TAG,
//                           "owned");
//    } else {
//        json_result.insert(XMPP_PASSWORD_TAG,
//                           "not owned");
//    }
//    //}

//    Knm::Setting::secretsTypes type;

//    type = (Knm::Setting::secretsTypes)dataMap[NM_IPOP_KEY_XMPP_PASSWORD"-flags"].toInt();
//    if (type & Knm::Setting::AgentOwned) {
//        json_result.insert(XMPP_PASSWORD_TAG,
//                secretData.value(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD)));
//    } else if (type & Knm::Setting::None) {
//        json_result.insert(XMPP_PASSWORD_TAG, "none");
//    } else {
//        json_result.insert(XMPP_PASSWORD_TAG, "not owned");
//    }


    if (!dataMap[NM_IPOP_KEY_IP4_ADDRESS].isEmpty()) {
        json_result.insert(IP4_ADDRESS_TAG,
                           dataMap[NM_IPOP_KEY_IP4_ADDRESS]);
    }

    if (!dataMap[NM_IPOP_KEY_IP4_NETMASK].isEmpty()) {
        if (dataMap[NM_IPOP_KEY_IP4_NETMASK].startsWith("255.")) {
            struct in_addr addr;
            if (inet_pton(AF_INET,
                    dataMap[NM_IPOP_KEY_IP4_NETMASK].toStdString().c_str(),
                    &addr) == 1) {
                int netmask = nm_utils_ip4_netmask_to_prefix(addr.s_addr);
                json_result.insert(IP4_NETMASK_TAG, netmask);
            }
        } else {
            json_result.insert(IP4_NETMASK_TAG,
                               dataMap[NM_IPOP_KEY_IP4_NETMASK].toInt());
        }
    }

    // create json string
    QJson::Serializer json_serializer;
    json_serializer.setIndentMode(QJson::IndentFull);
    bool ok;
    QByteArray json_string = json_serializer.serialize(json_result, &ok);

    if (!ok) {
        mError = VpnUiPlugin::Error;
        mErrorMessage = i18n("Could not create json string");
        expFile.close();
        return false;
    } else {
        expFile.write(json_string.data());
    }

    expFile.close();

    return true;
}
