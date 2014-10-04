/*
 * This file was generated by qdbusxml2cpp version 0.7
 * Command line was: qdbusxml2cpp -N -m -p nm-dhcp4-configinterface introspection/nm-dhcp4-config.xml
 *
 * qdbusxml2cpp is Copyright (C) 2011 Nokia Corporation and/or its subsidiary(-ies).
 *
 * This is an auto-generated file.
 * Do not edit! All changes made to it will be lost.
 */

#ifndef NM_DHCP4_CONFIGINTERFACE_H_1305477009
#define NM_DHCP4_CONFIGINTERFACE_H_1305477009

#include <QtCore/QObject>
#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariant>
#include <QtDBus/QtDBus>

/*
 * Proxy class for interface org.freedesktop.NetworkManager.DHCP4Config
 */
class OrgFreedesktopNetworkManagerDHCP4ConfigInterface: public QDBusAbstractInterface
{
    Q_OBJECT
public:
    static inline const char *staticInterfaceName()
    { return "org.freedesktop.NetworkManager.DHCP4Config"; }

public:
    OrgFreedesktopNetworkManagerDHCP4ConfigInterface(const QString &service, const QString &path, const QDBusConnection &connection, QObject *parent = 0);

    ~OrgFreedesktopNetworkManagerDHCP4ConfigInterface();

    Q_PROPERTY(QVariantMap Options READ options)
    inline QVariantMap options() const
    { return qvariant_cast< QVariantMap >(property("Options")); }

public Q_SLOTS: // METHODS
Q_SIGNALS: // SIGNALS
    void PropertiesChanged(const QVariantMap &properties);
};

#endif