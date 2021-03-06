/*
 * This file was generated by qdbusxml2cpp version 0.7
 * Command line was: qdbusxml2cpp -N -m -p nm-dhcp6-configinterface introspection/nm-dhcp6-config.xml
 *
 * qdbusxml2cpp is Copyright (C) 2011 Nokia Corporation and/or its subsidiary(-ies).
 *
 * This is an auto-generated file.
 * Do not edit! All changes made to it will be lost.
 */

#ifndef NM_DHCP6_CONFIGINTERFACE_H_1305477054
#define NM_DHCP6_CONFIGINTERFACE_H_1305477054

#include <QtCore/QObject>
#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariant>
#include <QtDBus/QtDBus>

/*
 * Proxy class for interface org.freedesktop.NetworkManager.DHCP6Config
 */
class OrgFreedesktopNetworkManagerDHCP6ConfigInterface: public QDBusAbstractInterface
{
    Q_OBJECT
public:
    static inline const char *staticInterfaceName()
    { return "org.freedesktop.NetworkManager.DHCP6Config"; }

public:
    OrgFreedesktopNetworkManagerDHCP6ConfigInterface(const QString &service, const QString &path, const QDBusConnection &connection, QObject *parent = 0);

    ~OrgFreedesktopNetworkManagerDHCP6ConfigInterface();

    Q_PROPERTY(QVariantMap Options READ options)
    inline QVariantMap options() const
    { return qvariant_cast< QVariantMap >(property("Options")); }

public Q_SLOTS: // METHODS
Q_SIGNALS: // SIGNALS
    void PropertiesChanged(const QVariantMap &properties);
};

#endif
