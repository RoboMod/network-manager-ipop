/*
 * This file was generated by qdbusxml2cpp version 0.7
 * Command line was: qdbusxml2cpp -N -m -c NetworkManagementInterface -p networkmanagementinterface /home/andreas/Programing/C++/network-manager-ipop/kde/libs/service/interfaces/org.kde.networkmanagement.xml
 *
 * qdbusxml2cpp is Copyright (C) 2012 Digia Plc and/or its subsidiary(-ies).
 *
 * This is an auto-generated file.
 * This file may have been hand-edited. Look for HAND-EDIT comments
 * before re-generating it.
 */

#include "networkmanagementinterface.h"

/*
 * Implementation of interface class NetworkManagementInterface
 */

NetworkManagementInterface::NetworkManagementInterface(const QString &service, const QString &path, const QDBusConnection &connection, QObject *parent)
    : QDBusAbstractInterface(service, path, staticInterfaceName(), connection, parent)
{
}

NetworkManagementInterface::~NetworkManagementInterface()
{
}


#include "networkmanagementinterface.moc"
