/*
Copyright 2008 Will Stephenson <wstephenson@kde.org>

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

#include "ipopwidget.h"
#include "nm-ipop-service.h"

#include <KDebug>
#include <KStandardDirs>
#include "connection.h"

class IPOPSettingWidget::Private
{
public:
    Ui_IPOPProp ui;
    Knm::VpnSetting* setting;
    bool readConfig;
    class EnumPasswordStorageType {
    public:
        enum PasswordStorageType {AlwaysAsk = 0, Store, NotRequired};
    };
};

IPOPSettingWidget::IPOPSettingWidget(Knm::Connection * connection, QWidget * parent)
    : SettingWidget(connection, parent), d(new Private) {
    d->ui.setupUi(this);
    d->setting = static_cast<Knm::VpnSetting *>(connection->setting(Knm::Setting::Vpn));
    d->readConfig = false;

    connect(d->ui.xmpp_password_type_combo, SIGNAL(currentIndexChanged(int)), this, SLOT(xmppPasswordStorageChanged(int)));
}

IPOPSettingWidget::~IPOPSettingWidget() {
    delete d;
}

void IPOPSettingWidget::init() {}

void IPOPSettingWidget::readConfig() {
    kDebug();

    // get settings
    QStringMap dataMap = d->setting->data();

    // write settings to ui
    d->ui.xmpp_host->setText(dataMap[NM_IPOP_KEY_XMPP_HOST]);
    d->ui.xmpp_username->setUrl(dataMap[NM_IPOP_KEY_XMPP_USERNAME]);
    d->ui.ip4_address->setUrl(dataMap[NM_IPOP_KEY_IP4_ADDRESS]);
    d->ui.ip4_netmask->setUrl(dataMap[NM_IPOP_KEY_IP4_NETMASK]);

    d->readConfig = true;
}

void IPOPSettingWidget::writeConfig() {
    kDebug();

    d->setting->setServiceType(QLatin1String(NM_DBUS_SERVICE_IPOP));

    QStringMap data;
    QStringMap secretData;

    // insert data from ui
    data.insert(QLatin1String(NM_IPOP_KEY_XMPP_HOST), d->ui.xmpp_host->text());
    data.insert(QLatin1String(NM_IPOP_KEY_XMPP_USERNAME), d->ui.xmpp_username->text());
    if (!d->ui.xmpp_password->text().isEmpty()) {
        secretData.insert(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD), d->ui.xmpp_password->text());
    }
    handleOnePasswordType(d->ui.xmpp_password_type_combo, QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD"-flags"), data);
    data.insert(QLatin1String(NM_IPOP_KEY_IP4_ADDRESS), d->ui.ip4_address->text());
    data.insert(QLatin1String(NM_IPOP_KEY_IP4_NETMASK), d->ui.ip4_netmask->text());

    d->setting->setData(data);
    d->setting->setVpnSecrets(secretData);
}

void IPOPSettingWidget::readSecrets() {
    QStringMap secrets = d->setting->vpnSecrets();
    QStringMap dataMap = d->setting->data();
    Knm::Setting::secretsTypes type;

    type = (Knm::Setting::secretsTypes)dataMap[NM_IPOP_KEY_XMPP_PASSWORD"-flags"].toInt();
    if (type & Knm::Setting::AgentOwned || type & Knm::Setting::None) {
        d->ui.xmpp_password->setText(secrets.value(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD)));
    }
    fillOnePasswordCombo(d->ui.xmpp_password_type_combo, type);
}

void IPOPSettingWidget::validate() {}


void IPOPSettingWidget::xmppPasswordStorageChanged(int index) {
    setPasswordType(d->ui.xmpp_password, index);
}

void IPOPSettingWidget::setPasswordType(QLineEdit *edit, int type) {
    switch (type) {
        case Private::EnumPasswordStorageType::AlwaysAsk:
        case Private::EnumPasswordStorageType::NotRequired:
            edit->setEnabled(false);
            break;
        case Private::EnumPasswordStorageType::Store:
            edit->setEnabled(true);
            break;
    }
}

void IPOPSettingWidget::fillOnePasswordCombo(QComboBox * combo, Knm::Setting::secretsTypes type) {
    if (type.testFlag(Knm::Setting::AgentOwned) || type.testFlag(Knm::Setting::None)) {
        combo->setCurrentIndex(Private::EnumPasswordStorageType::Store);
    } else if (type.testFlag(Knm::Setting::NotRequired)) {
        combo->setCurrentIndex(Private::EnumPasswordStorageType::NotRequired);
    } else if (type.testFlag(Knm::Setting::NotSaved)) {
        combo->setCurrentIndex(Private::EnumPasswordStorageType::AlwaysAsk);
    }
}

uint IPOPSettingWidget::handleOnePasswordType(const QComboBox * combo, const QString & key,
                                              QStringMap& data) {
    uint type = combo->currentIndex();
    switch (type) {
        case Private::EnumPasswordStorageType::AlwaysAsk:
            data.insert(key, QString::number(Knm::Setting::NotSaved));
            break;
        case Private::EnumPasswordStorageType::Store:
            data.insert(key, QString::number(Knm::Setting::AgentOwned));
            break;
        case Private::EnumPasswordStorageType::NotRequired:
            data.insert(key, QString::number(Knm::Setting::NotRequired));
            break;
    }
    return type;
}

// vim: sw=4 sts=4 et tw=100

