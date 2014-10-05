/* ipopauth.cpp - authentication widget to ask user for password
 *
 * Copyright 2011 Ilia Kats <ilia-kats@gmx.net>
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

#include "ipopauth.h"

#include <QString>
#include <QFormLayout>
#include <QLabel>
#include <QCheckBox>
#include <KLineEdit>
#include <KLocale>
#include "nm-ipop-service.h"

#include "connection.h"

class IPOPAuthWidgetPrivate
{
public:
    Knm::VpnSetting * setting;
    QFormLayout *layout;
};

IPOPAuthWidget::IPOPAuthWidget(Knm::Connection * connection, QWidget * parent)
    : SettingWidget(connection, parent), d_ptr(new IPOPAuthWidgetPrivate) {
    Q_D(IPOPAuthWidget);
    d->setting =
        static_cast<Knm::VpnSetting *>(connection->setting(Knm::Setting::Vpn));
    d->layout = new QFormLayout(this);
    this->setLayout(d->layout);
}

IPOPAuthWidget::~IPOPAuthWidget() {
    delete d_ptr;
}

void IPOPAuthWidget::readSecrets() {
    Q_D(IPOPAuthWidget);
    QStringMap secrets = d->setting->vpnSecrets();
    QStringMap dataMap = d->setting->data();

    QLabel *label;
    KLineEdit *lineEdit;

    Knm::Setting::secretsTypes passType =
        (Knm::Setting::secretsTypes)dataMap[NM_IPOP_KEY_XMPP_PASSWORD"-flags"].toInt();

    label = new QLabel(this);
    label->setText(i18n("Password:"));
    lineEdit = new KLineEdit(this);
    lineEdit->setPasswordMode(true);
    lineEdit->setProperty("nm_secrets_key",
                          QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD));
    lineEdit->setText(secrets.value(QLatin1String(NM_IPOP_KEY_XMPP_PASSWORD)));
    d->layout->addRow(label, lineEdit);

    for (int i = 0; i < d->layout->rowCount(); i++)
    {
        KLineEdit *le =
            qobject_cast<KLineEdit*>(d->layout->itemAt(i, QFormLayout::FieldRole)->widget());
        if (le && le->text().isEmpty()) {
            le->setFocus(Qt::OtherFocusReason);
            break;
        }
    }

    QCheckBox *showPasswords = new QCheckBox(this);
    showPasswords->setText(i18n("&Show password"));
    d->layout->addRow(showPasswords);
    connect(showPasswords, SIGNAL(toggled(bool)),
            this, SLOT(showPasswordsToggled(bool)));
}

void IPOPAuthWidget::writeConfig() {
    Q_D(IPOPAuthWidget);

    QStringMap secretData;
    for (int i = 0; i < d->layout->rowCount() - 1; i++)
    {
        KLineEdit *le =
            qobject_cast<KLineEdit*>(d->layout->itemAt(i, QFormLayout::FieldRole)->widget());
        if (le && !le->text().isEmpty()) {
            QString key = le->property("nm_secrets_key").toString();
            secretData.insert(key, le->text());
        }
    }

    d->setting->setVpnSecrets(secretData);
}

void IPOPAuthWidget::showPasswordsToggled(bool toggled) {
    Q_D(IPOPAuthWidget);
    for (int i = 0; i < d->layout->rowCount() - 1; i++)
    {
        KLineEdit *le =
            qobject_cast<KLineEdit*>(d->layout->itemAt(i, QFormLayout::FieldRole)->widget());
        if (le) {
            le->setPasswordMode(!toggled);
        }
    }
}
