/*
 * This file was generated by qdbusxml2cpp version 0.7
 * Command line was: qdbusxml2cpp -N -m -c ActivatableInterface -p activatableinterface /home/andreas/Programing/C++/network-manager-ipop/kde/libs/service/interfaces/org.kde.networkmanagement.activatable.xml
 *
 * qdbusxml2cpp is Copyright (C) 2012 Digia Plc and/or its subsidiary(-ies).
 *
 * This is an auto-generated file.
 * Do not edit! All changes made to it will be lost.
 */

#ifndef ACTIVATABLEINTERFACE_H
#define ACTIVATABLEINTERFACE_H

#include <QtCore/QObject>
#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariant>
#include <QtDBus/QtDBus>

/*
 * Proxy class for interface org.kde.networkmanagement.Activatable
 */
class ActivatableInterface: public QDBusAbstractInterface
{
    Q_OBJECT
public:
    static inline const char *staticInterfaceName()
    { return "org.kde.networkmanagement.Activatable"; }

public:
    ActivatableInterface(const QString &service, const QString &path, const QDBusConnection &connection, QObject *parent = 0);

    ~ActivatableInterface();

    Q_PROPERTY(QString deviceUni READ deviceUni)
    inline QString deviceUni() const
    { return qvariant_cast< QString >(property("deviceUni")); }

    Q_PROPERTY(uint type READ type)
    inline uint type() const
    { return qvariant_cast< uint >(property("type")); }

public Q_SLOTS: // METHODS
    inline QDBusPendingReply<uint> activatableType()
    {
        QList<QVariant> argumentList;
        return asyncCallWithArgumentList(QLatin1String("activatableType"), argumentList);
    }

    inline QDBusPendingReply<> activate()
    {
        QList<QVariant> argumentList;
        return asyncCallWithArgumentList(QLatin1String("activate"), argumentList);
    }

    inline QDBusPendingReply<QString> deviceUni()
    {
        QList<QVariant> argumentList;
        return asyncCallWithArgumentList(QLatin1String("deviceUni"), argumentList);
    }

    inline QDBusPendingReply<bool> isShared()
    {
        QList<QVariant> argumentList;
        return asyncCallWithArgumentList(QLatin1String("isShared"), argumentList);
    }

Q_SIGNALS: // SIGNALS
    void activated();
    void changed();
    void propertiesChanged(const QVariantMap &properties);
};

#endif
