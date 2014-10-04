/*
Copyright 2008 Will Stephenson <wstephenson@kde.org>
Copyright 2011-2012 Rajeesh K Nambiar <rajeeshknambiar@gmail.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of
the License or (at your option) version 3 or any later version
accepted by the membership of KDE e.V. (or its successor approved
by the membership of KDE e.V.), which shall act as a proxy
defined in Section 14 of version 3 of the license.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "ipop.h"

#include <KPluginFactory>
#include <KMessageBox>

#include <nm-setting-ip4-config.h>

#include "ipopwidget.h"
#include "ipopauth.h"

#include "connection.h"
#include <types.h>
#include "nm-ipop-service.h"
#include "settings/vpn.h"
#include "settings/ipv4.h"

K_PLUGIN_FACTORY( IPOPUiPluginFactory, registerPlugin<IPOPUiPlugin>(); )
K_EXPORT_PLUGIN( IPOPUiPluginFactory( "networkmanagement_ipopui", "libknetworkmanager" ) )

IPOPUiPlugin::IPOPUiPlugin(QObject * parent, const QVariantList &) : VpnUiPlugin(parent) {}

IPOPUiPlugin::~IPOPUiPlugin() {}

SettingWidget* IPOPUiPlugin::widget(Knm::Connection * connection, QWidget * parent) {
    IPOPSettingWidget * wid = new IPOPSettingWidget(connection, parent);
    wid->init();
    return wid;
}

SettingWidget* IPOPUiPlugin::askUser(Knm::Connection * connection, QWidget * parent) {
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

//    QVariantList conSetting;
//    QStringMap dataMap;
//    QStringMap secretData;
//    QStringMap ipv4Data;

//    QString proxy_type;
//    QString proxy_user;
//    QString proxy_passwd;
//    bool have_client = false;
//    bool have_remote = false;
//    bool proxy_set = false;
//    bool have_pass = false;
//    bool have_sk = false;

//    QTextStream in(&impFile);
//    while (!in.atEnd()) {
//        QStringList key_value;
//        QString line = in.readLine();
//        // Skip comments
//        if (line.indexOf('#') >= 0)
//            line.truncate(line.indexOf('#'));
//        if (line.indexOf(';') >= 0)
//            line.truncate(line.indexOf(';'));
//        if (line.isEmpty())
//            continue;
//        key_value.clear();
//        key_value << line.split(QRegExp("\\s")); // Split at whitespace

//        if (key_value[0] == CLIENT_TAG || key_value[0] == TLS_CLIENT_TAG) {
//            have_client = true;
//            continue;
//        }
//        if (key_value[0] == DEV_TAG) {
//            if (key_value.count() == 2) {
//                if (key_value[1].startsWith("tun")) {
//                    // ignore; default is tun
//                }
//                else if (key_value[1].startsWith("tap")) {
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_TAP_DEV), "yes");
//                }
//                else {
//                    KMessageBox::information(0, i18n("Unknown option: %1", line));
//                }
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == PROTO_TAG) {
//            if (key_value.count() == 2) {
//                /* Valid parameters are "udp", "tcp-client" and "tcp-server".
//                 * 'tcp' isn't technically valid, but it used to be accepted so
//                 * we'll handle it here anyway.
//                 */
//                if (key_value[1] == "udp") {
//                    // ignore; default is udp
//                }
//                else if (key_value[1] == "tcp-client" || key_value[1] == "tcp-server" || key_value[1] == "tcp") {
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PROTO_TCP), "yes");
//                }
//                else {
//                    KMessageBox::information(0, i18n("Unknown option: %1", line));
//                }
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == MSSFIX_TAG) {
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_MSSFIX), "yes");
//            continue;
//        }
//        if (key_value[0] == TUNMTU_TAG) {
//            if (key_value.count() == 2) {
//                if (key_value[1].toLong() >= 0 && key_value[1].toLong() < 0xFFFF ) {
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_TUNNEL_MTU), key_value[1]);
//                }
//                else {
//                    KMessageBox::information(0, i18n("Invalid size (should be between 0 and 0xFFFF) in option: %1", line));
//                }
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == FRAGMENT_TAG) {
//            if (key_value.count() == 2) {
//                if (key_value[1].toLong() >= 0 && key_value[1].toLong() < 0xFFFF ) {
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_FRAGMENT_SIZE), key_value[1]);
//                }
//                else {
//                    KMessageBox::information(0, i18n("Invalid size (should be between 0 and 0xFFFF) in option: %1", line));
//                }
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == COMP_TAG) {
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_COMP_LZO), "yes");
//            continue;
//        }
//        if (key_value[0] == RENEG_SEC_TAG) {
//            if (key_value.count() == 2) {
//                if (key_value[1].toLong() >= 0 && key_value[1].toLong() <= 604800 ) {
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_RENEG_SECONDS), key_value[1]);
//                }
//                else {
//                    KMessageBox::information(0, i18n("Invalid size (should be between 0 and 604800) in option: %1", line));
//                }
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == HTTP_PROXY_RETRY_TAG || key_value[0] == SOCKS_PROXY_RETRY_TAG) {
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PROXY_RETRY), "yes");
//            continue;
//        }
//        if (key_value[0] == HTTP_PROXY_TAG)
//            proxy_type = "http";
//        if (key_value[0] == SOCKS_PROXY_TAG)
//            proxy_type = "socks";
//        if (!proxy_type.isEmpty() && !proxy_set && key_value.count() >= 3) {
//            bool success = true;
//            if (proxy_type == "http" && key_value.count() >= 4) {
//                // Parse the HTTP proxy file
//                QFile httpProxyFile(QFileInfo(fileName).dir().absolutePath() + '/' + key_value[3]);
//                if (httpProxyFile.open(QFile::ReadOnly|QFile::Text)) {
//                    QTextStream httpProxyIn(&httpProxyFile);
//                    while (!httpProxyIn.atEnd()) {
//                        QString httpProxyLine = httpProxyIn.readLine();
//                        if (httpProxyLine.isEmpty())
//                            continue;
//                        if (proxy_user.isEmpty())
//                            proxy_user = httpProxyLine;
//                        if (proxy_passwd.isEmpty()) {
//                            proxy_passwd = httpProxyLine;
//                            break;
//                        }
//                    }
//                    if (proxy_user.isEmpty()||proxy_passwd.isEmpty())
//                        success = false;
//                }
//            }
//            if (success && !proxy_type.isEmpty() && key_value[2].toLong() > 0 // Port
//                                                 && key_value[2].toLong() < 65536) {
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PROXY_TYPE), proxy_type);
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PROXY_SERVER), key_value[1]);  // Proxy server
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PROXY_PORT), key_value[2]);    // Port
//                if (!proxy_user.isEmpty())
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_HTTP_PROXY_USERNAME), proxy_user);
//                if (!proxy_passwd.isEmpty()) {
//                    secretData.insert(QLatin1String(NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD), proxy_passwd);
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags"), QString::number(Knm::Setting::NotSaved));
//                }
//                proxy_set = true;
//            }
//            if (!success)
//                KMessageBox::information(0, i18n("Invalid proxy option: %1", line));
//            continue;
//        }
//        if (key_value[0] == REMOTE_TAG) {
//            if (key_value.count() >= 2 && key_value.count() <= 4) {
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_REMOTE), key_value[1]);
//                have_remote = true;
//                if (key_value.count() >= 3 && key_value[2].toLong() > 0
//                                           && key_value[2].toLong() < 65536) {
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PORT), key_value[2]);
//                    if (key_value.count() == 4) {
//                        // TODO
//                    }
//                }
//            }
//        }
//        if (key_value[0] == PORT_TAG || key_value[0] == RPORT_TAG) {
//            // Port specified in 'remote' always takes precedence
//            if (!dataMap.contains(NM_OPENVPN_KEY_PORT)) {
//                if (key_value.count() == 2 ) {
//                    if (key_value[1].toLong() > 0 && key_value[1].toLong() < 65536)
//                        dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PORT), key_value[1]);
//                    else
//                        KMessageBox::information(0, i18n("Invalid port (should be between 1 and 65535) in option: %1", line));
//                }
//                else
//                    KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == PKCS12_TAG && key_value.count() > 1) {
//            key_value[1] = line.right(line.length() - line.indexOf(QRegExp("\\s"))); // Get whole string after key
//            QString certFile = unQuote(key_value[1], fileName);
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_CA), certFile);
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_CERT), certFile);
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_KEY), certFile);
//            continue;
//        }
//        if (key_value[0] == CA_TAG && key_value.count() > 1) {
//            key_value[1] = line.right(line.length() - line.indexOf(QRegExp("\\s"))); // Get whole string after key
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_CA), unQuote(key_value[1], fileName));
//            continue;
//        }
//        if (key_value[0] == CERT_TAG && key_value.count() > 1) {
//            key_value[1] = line.right(line.length() - line.indexOf(QRegExp("\\s"))); // Get whole string after key
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_CERT), unQuote(key_value[1], fileName));
//            continue;
//        }
//        if (key_value[0] == KEY_TAG && key_value.count() > 1) {
//            key_value[1] = line.right(line.length() - line.indexOf(QRegExp("\\s"))); // Get whole string after key
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_KEY), unQuote(key_value[1], fileName));
//            continue;
//        }
//        if (key_value[0] == SECRET_TAG && key_value.count() > 1) {
//            key_value[1] = line.right(line.length() - line.indexOf(QRegExp("\\s"))); // Get whole string after key
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_STATIC_KEY), unQuote(key_value[1], fileName));
//            if (key_value.count() > 2) {
//                key_value[2] = key_value[1];
//                if (!key_value[2].isEmpty() && (key_value[2].toLong() == 0 ||key_value[2].toLong() == 1))
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_STATIC_KEY_DIRECTION), key_value[2]);
//            }
//            have_sk = true;
//            continue;
//        }
//        if (key_value[0] == TLS_AUTH_TAG && key_value.count() >1) {
//            key_value[1] = line.right(line.length() - line.indexOf(QRegExp("\\s"))); // Get whole string after key
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_TA), unQuote(key_value[1], fileName));
//            if (key_value.count() > 2) {
//                key_value[2] = key_value[1];
//                if (!key_value[2].isEmpty() && (key_value[2].toLong() == 0 ||key_value[2].toLong() == 1))
//                    dataMap.insert(QLatin1String(NM_OPENVPN_KEY_TA_DIR), key_value[2]);
//            }
//            continue;
//        }
//        if (key_value[0] == CIPHER_TAG) {
//            if (key_value.count() == 2) {
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_CIPHER), key_value[1]);
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == TLS_REMOTE_TAG) {
//            if (!unQuote(key_value[1], fileName).isEmpty()) {
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_TLS_REMOTE), key_value[1]);
//            }
//            else {
//                KMessageBox::information(0, i18n("Unknown option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == IFCONFIG_TAG) {
//            if (key_value.count() == 3) {
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_LOCAL_IP), key_value[1]);
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_REMOTE_IP), key_value[2]);
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 2) in option: %1", line));
//            }
//            continue;
//        }
//        if (key_value[0] == AUTH_USER_PASS_TAG) {
//            have_pass = true;
//        }
//        if (key_value[0] == AUTH_TAG) {
//            if (key_value.count() == 2) {
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_AUTH), key_value[1]);
//            }
//            else {
//                KMessageBox::information(0, i18n("Invalid number of arguments (expected 1) in option: %1", line));
//            }
//            continue;
//        }
//        // Import X-NM-Routes if present
//        if (key_value[0] == "X-NM-Routes") {
//            ipv4Data.insert(NM_SETTING_IP4_CONFIG_ROUTES, key_value[1]);
//            continue;
//        }
//    }
//    if (!have_client && !have_sk) {
//        mError = VpnUiPlugin::Error;
//        mErrorMessage = i18n("File %1 is not a valid OpenVPN's client configuration file", fileName);
//        return conSetting;
//    }
//    else if (!have_remote) {
//        mError = VpnUiPlugin::Error;
//        mErrorMessage = i18n("File %1 is not a valid OpenVPN configuration (no remote).", fileName);
//        return conSetting;
//    }
//    else {
//        QString conType;
//        bool have_certs = false;
//        bool have_ca = false;

//        if (dataMap.contains(NM_OPENVPN_KEY_CA))
//            have_ca = true;
//        if (have_ca && dataMap.contains(NM_OPENVPN_KEY_CERT) && dataMap.contains(NM_OPENVPN_KEY_KEY))
//            have_certs = true;
//        // Determine connection type
//        if (have_pass) {
//            if (have_certs)
//                conType = NM_OPENVPN_CONTYPE_PASSWORD_TLS;
//            else if (have_ca)
//                conType = NM_OPENVPN_CONTYPE_PASSWORD;
//        }
//        else if (have_certs) {
//            conType = NM_OPENVPN_CONTYPE_TLS;
//        }
//        else if (have_sk) {
//            conType = NM_OPENVPN_CONTYPE_STATIC_KEY;
//        }
//        if (conType.isEmpty())
//            conType = NM_OPENVPN_CONTYPE_TLS;
//        dataMap.insert(QLatin1String(NM_OPENVPN_KEY_CONNECTION_TYPE), conType);
//        // Default secret flags to be agent-owned
//        if (have_pass)
//            dataMap.insert(QLatin1String(NM_OPENVPN_KEY_PASSWORD"-flags"), QString::number(Knm::Setting::NotSaved));
//        if (have_certs) {
//            if (dataMap.contains(NM_OPENVPN_KEY_KEY) && isEncrypted(dataMap[NM_OPENVPN_KEY_KEY]))
//                dataMap.insert(QLatin1String(NM_OPENVPN_KEY_CERTPASS"-flags"), QString::number(Knm::Setting::NotSaved));
//        }
//    }

//    conSetting << Knm::VpnSetting::variantMapFromStringList(Knm::VpnSetting::stringMapToStringList(dataMap));
//    conSetting << Knm::VpnSetting::variantMapFromStringList(Knm::VpnSetting::stringMapToStringList(secretData));
//    conSetting << QFileInfo(fileName).completeBaseName(); // Connection name
//    if (!ipv4Data.isEmpty()) {
//        conSetting << Knm::VpnSetting::variantMapFromStringList(Knm::VpnSetting::stringMapToStringList(ipv4Data));
//    }
//    return conSetting;
    return QVariantList();
}

bool IPOPUiPlugin::exportConnectionSettings(Knm::Connection * connection, const QString &fileName)
{
//    QFile expFile(fileName);
//    if (! expFile.open(QIODevice::WriteOnly | QIODevice::Text) ) {
//        mError = VpnUiPlugin::Error;
//        mErrorMessage = i18n("Could not open file for writing");
//        return false;
//    }

//    QStringMap dataMap;
//    QStringMap secretData;

//    Knm::VpnSetting * vpnSetting = static_cast<Knm::VpnSetting*>(connection->setting(Knm::Setting::Vpn));
//    dataMap = vpnSetting->data();
//    secretData = vpnSetting->vpnSecrets();

//    QString line;
//    QString cacert, user_cert, private_key;

//    line = QString(CLIENT_TAG) + '\n';
//    expFile.write(line.toLatin1());
//    line = QString(REMOTE_TAG) + ' ' + dataMap[NM_OPENVPN_KEY_REMOTE] +
//           (dataMap[NM_OPENVPN_KEY_PORT].isEmpty() ? "\n" : (' ' + dataMap[NM_OPENVPN_KEY_PORT]) + '\n');
//    expFile.write(line.toLatin1());
//    if (dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_TLS ||
//            dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_PASSWORD ||
//            dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_PASSWORD_TLS) {
//        if (!dataMap[NM_OPENVPN_KEY_CA].isEmpty())
//            cacert = dataMap[NM_OPENVPN_KEY_CA];
//    }
//    if (dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_TLS ||
//            dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_PASSWORD_TLS) {
//        if (!dataMap[NM_OPENVPN_KEY_CERT].isEmpty())
//            user_cert = dataMap[NM_OPENVPN_KEY_CERT];
//        if (!dataMap[NM_OPENVPN_KEY_KEY].isEmpty())
//            private_key = dataMap[NM_OPENVPN_KEY_KEY];

//    }
//    // Handle PKCS#12 (all certs are the same file)
//    if (!cacert.isEmpty() && !user_cert.isEmpty() && !private_key.isEmpty()
//                          && cacert == user_cert && cacert == private_key) {
//        line = QString("%1 \"%2\"\n").arg(PKCS12_TAG, cacert);
//        expFile.write(line.toLatin1());
//    }
//    else {
//        if (!cacert.isEmpty()) {
//            line = QString("%1 \"%2\"\n").arg(CA_TAG, cacert);
//            expFile.write(line.toLatin1());
//        }
//        if (!user_cert.isEmpty()) {
//            line = QString("%1 \"%2\"\n").arg(CERT_TAG, user_cert);
//            expFile.write(line.toLatin1());
//        }
//        if (!private_key.isEmpty()) {
//            line = QString("%1 \"%2\"\n").arg(KEY_TAG, private_key);
//            expFile.write(line.toLatin1());
//        }
//    }
//    if (dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_PASSWORD ||
//            dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_PASSWORD_TLS) {
//        line = QString(AUTH_USER_PASS_TAG) + '\n';
//        expFile.write(line.toLatin1());
//        if (!dataMap[NM_OPENVPN_KEY_TLS_REMOTE].isEmpty()) {
//            line = QString(TLS_REMOTE_TAG) + " \"" + dataMap[NM_OPENVPN_KEY_TLS_REMOTE] + "\"\n";
//            expFile.write(line.toLatin1());
//        }
//        if (!dataMap[NM_OPENVPN_KEY_TA].isEmpty()) {
//            line = QString(TLS_AUTH_TAG) + " \"" + dataMap[NM_OPENVPN_KEY_TA] + '\"' + (dataMap[NM_OPENVPN_KEY_TA_DIR].isEmpty() ?
//                                "\n" : (' ' + dataMap[NM_OPENVPN_KEY_TA_DIR]) + '\n');
//            expFile.write(line.toLatin1());
//        }
//    }
//    if (dataMap[NM_OPENVPN_KEY_CONNECTION_TYPE] == NM_OPENVPN_CONTYPE_STATIC_KEY) {
//        line = QString(SECRET_TAG) + " \"" + dataMap[NM_OPENVPN_KEY_STATIC_KEY] + '\"' + (dataMap[NM_OPENVPN_KEY_STATIC_KEY_DIRECTION].isEmpty() ?
//                          "\n" : (' ' + dataMap[NM_OPENVPN_KEY_STATIC_KEY_DIRECTION]) + '\n');
//        expFile.write(line.toLatin1());
//    }
//    if (dataMap.contains(NM_OPENVPN_KEY_RENEG_SECONDS) && !dataMap[NM_OPENVPN_KEY_RENEG_SECONDS].isEmpty()) {
//        line = QString(RENEG_SEC_TAG) + ' ' + dataMap[NM_OPENVPN_KEY_RENEG_SECONDS] + '\n';
//        expFile.write(line.toLatin1());
//    }
//    if (!dataMap[NM_OPENVPN_KEY_CIPHER].isEmpty()) {
//        line = QString(CIPHER_TAG) + ' ' + dataMap[NM_OPENVPN_KEY_CIPHER] + '\n';
//        expFile.write(line.toLatin1());
//    }
//    if (dataMap[NM_OPENVPN_KEY_COMP_LZO] == "yes") {
//        line = QString(COMP_TAG) + " yes\n";
//        expFile.write(line.toLatin1());
//    }
//    if (dataMap[NM_OPENVPN_KEY_MSSFIX] == "yes") {
//        line = QString(MSSFIX_TAG) + '\n';
//        expFile.write(line.toLatin1());
//    }
//    if (!dataMap[NM_OPENVPN_KEY_TUNNEL_MTU].isEmpty()) {
//        line = QString(TUNMTU_TAG) + ' ' + dataMap[NM_OPENVPN_KEY_TUNNEL_MTU] + '\n';
//        expFile.write(line.toLatin1());
//    }
//    if (!dataMap[NM_OPENVPN_KEY_FRAGMENT_SIZE].isEmpty()) {
//        line = QString(FRAGMENT_TAG) + ' ' + dataMap[NM_OPENVPN_KEY_FRAGMENT_SIZE] + '\n';
//        expFile.write(line.toLatin1());
//    }
//    line = QString(DEV_TAG) + (dataMap[NM_OPENVPN_KEY_TAP_DEV] == "yes" ? " tap\n" : " tun\n");
//    expFile.write(line.toLatin1());
//    line = QString(PROTO_TAG) + (dataMap[NM_OPENVPN_KEY_PROTO_TCP] == "yes" ? " tcp\n" : " udp\n");
//    expFile.write(line.toLatin1());
//    // Proxy stuff
//    if (!dataMap[NM_OPENVPN_KEY_PROXY_TYPE].isEmpty()) {
//        QString proxy_port = dataMap[NM_OPENVPN_KEY_PROXY_PORT];
//        if (dataMap[NM_OPENVPN_KEY_PROXY_TYPE] == "http" && !dataMap[NM_OPENVPN_KEY_PROXY_SERVER].isEmpty()
//                                                         && dataMap.contains(NM_OPENVPN_KEY_PROXY_PORT)) {
//            if (proxy_port.toInt() == 0)
//                proxy_port = "8080";
//            line = QString(HTTP_PROXY_TAG) + ' ' + dataMap[NM_OPENVPN_KEY_PROXY_SERVER] + ' ' + proxy_port +
//                    (dataMap[NM_OPENVPN_KEY_HTTP_PROXY_USERNAME].isEmpty() ? "\n" : (' ' + fileName + "-httpauthfile") + '\n');
//            expFile.write(line.toLatin1());
//            if (dataMap[NM_OPENVPN_KEY_PROXY_RETRY] == "yes") {
//                line = QString(HTTP_PROXY_RETRY_TAG) + '\n';
//                expFile.write(line.toLatin1());
//            }
//            // If there is a username, need to write an authfile
//            if (!dataMap[NM_OPENVPN_KEY_HTTP_PROXY_USERNAME].isEmpty()) {
//                QFile authFile(fileName + "-httpauthfile");
//                if (authFile.open(QFile::WriteOnly | QFile::Text)) {
//                    line = dataMap[NM_OPENVPN_KEY_HTTP_PROXY_USERNAME] + (dataMap[NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD].isEmpty()?
//                                                                         "\n" : (dataMap[NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD] + '\n'));
//                    authFile.write(line.toLatin1());
//                    authFile.close();
//                }
//            }
//        }
//        else if (dataMap[NM_OPENVPN_KEY_PROXY_TYPE] == "socks" && !dataMap[NM_OPENVPN_KEY_PROXY_SERVER].isEmpty() && dataMap.contains(NM_OPENVPN_KEY_PROXY_PORT)) {
//            if (proxy_port.toInt() == 0)
//                proxy_port = "1080";
//            line = QString(SOCKS_PROXY_TAG) + dataMap[NM_OPENVPN_KEY_PROXY_SERVER] + ' ' + proxy_port + '\n';
//            expFile.write(line.toLatin1());
//            if (dataMap[NM_OPENVPN_KEY_PROXY_RETRY] == "yes") {
//                line = QString(SOCKS_PROXY_RETRY_TAG) + '\n';
//                expFile.write(line.toLatin1());
//            }
//        }
//    }
//    // Export X-NM-Routes
//    Knm::Ipv4Setting *ipv4Setting = static_cast<Knm::Ipv4Setting*>(connection->setting(Knm::Setting::Ipv4));
//    if (!ipv4Setting->routes().isEmpty()) {
//        QString routes;
//        foreach(const Solid::Control::IPv4RouteNm09 &oneRoute, ipv4Setting->routes()) {
//            routes += QHostAddress(oneRoute.route()).toString() + '/' + QString::number(oneRoute.prefix()) + ' ';
//        }
//        if (!routes.isEmpty()) {
//            routes = "X-NM-Routes " + routes.trimmed();
//            expFile.write(routes.toLatin1());
//        }
//    }
//    // Add hard-coded stuff
//    expFile.write("nobind\n"
//                  "auth-nocache\n"
//                  "script-security 2\n"
//                  "persist-key\n"
//                  "persist-tun\n"
//                  "user nobody\n"
//                  "group nobody\n");
//    expFile.close();
//    return true;
    return false;
}

// vim: sw=4 sts=4 et tw=100
