// This file is generated by kconfig_compiler from knmserviceprefs.kcfg.
// All changes you do to this file will be lost.
#ifndef KNETWORKMANAGERSERVICEPREFS_H
#define KNETWORKMANAGERSERVICEPREFS_H

#include "knminternals_export.h"

#include <kconfigskeleton.h>
#include <kdebug.h>

#include <kwallet.h>
#include "service/secretstorage.h"
class KNMINTERNALS_EXPORT KNetworkManagerServicePrefs : public KConfigSkeleton
{
  public:
    enum InterfaceNamingChoices { DescriptiveNames, SystemNames, VendorProductNames, TypeNames };
    enum NetworkSpeedUnitChoices { KBytes_s, KBits_s };
    enum AskForGsmPinChoices { OnModemDetection, WhenActivatingConnection };

    static KNetworkManagerServicePrefs *self();
    static void instance(const QString& cfgfilename);
    ~KNetworkManagerServicePrefs();

    /**
      Set Connections
    */
    static
    void setConnections( const QStringList & v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "Connections" ) ))
        self()->mConnections = v;
    }

    /**
      Get Connections
    */
    static
    QStringList connections()
    {
      return self()->mConnections;
    }

    /**
      Set Store secrets in wallet
    */
    static
    void setSecretStorageMode( int v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "SecretStorageMode" ) ))
        self()->mSecretStorageMode = v;
    }

    /**
      Get Store secrets in wallet
    */
    static
    int secretStorageMode()
    {
      return self()->mSecretStorageMode;
    }

    /**
      Set Autostart
    */
    static
    void setAutostart( bool v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "Autostart" ) ))
        self()->mAutostart = v;
    }

    /**
      Get Autostart
    */
    static
    bool autostart()
    {
      return self()->mAutostart;
    }

    /**
      Set InterfaceNamingStyle
    */
    static
    void setInterfaceNamingStyle( int v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "InterfaceNamingStyle" ) ))
        self()->mInterfaceNamingStyle = v;
    }

    /**
      Get InterfaceNamingStyle
    */
    static
    int interfaceNamingStyle()
    {
      return self()->mInterfaceNamingStyle;
    }

    /**
      Set NetworkSpeedUnit
    */
    static
    void setNetworkSpeedUnit( int v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "NetworkSpeedUnit" ) ))
        self()->mNetworkSpeedUnit = v;
    }

    /**
      Get NetworkSpeedUnit
    */
    static
    int networkSpeedUnit()
    {
      return self()->mNetworkSpeedUnit;
    }

    /**
      Set ShowAdvancedSettings
    */
    static
    void setShowAdvancedSettings( bool v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "ShowAdvancedSettings" ) ))
        self()->mShowAdvancedSettings = v;
    }

    /**
      Get ShowAdvancedSettings
    */
    static
    bool showAdvancedSettings()
    {
      return self()->mShowAdvancedSettings;
    }

    /**
      Set AskForGsmPin
    */
    static
    void setAskForGsmPin( int v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "AskForGsmPin" ) ))
        self()->mAskForGsmPin = v;
    }

    /**
      Get AskForGsmPin
    */
    static
    int askForGsmPin()
    {
      return self()->mAskForGsmPin;
    }

    /**
      Set IconCount
    */
    static
    void setIconCount( uint v )
    {
      if (v < 1)
      {
        kDebug() << "setIconCount: value " << v << " is less than the minimum value of 1";
        v = 1;
      }

      if (v > 5)
      {
        kDebug() << "setIconCount: value " << v << " is greater than the maximum value of 5";
        v = 5;
      }

      if (!self()->isImmutable( QString::fromLatin1( "IconCount" ) ))
        self()->mIconCount = v;
    }

    /**
      Get IconCount
    */
    static
    uint iconCount()
    {
      return self()->mIconCount;
    }

    /**
      Set IconTypes_$(IconIndex)
    */
    static
    void setIconTypes( int i, uint v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "IconTypes%1" ).arg( i ) ))
        self()->mIconTypes[i] = v;
    }

    /**
      Get IconTypes_$(IconIndex)
    */
    static
    uint iconTypes( int i )
    {
      return self()->mIconTypes[i];
    }

    /**
      Set ToolTipKeys
    */
    static
    void setToolTipKeys( const QStringList & v )
    {
      if (!self()->isImmutable( QString::fromLatin1( "ToolTipKeys" ) ))
        self()->mToolTipKeys = v;
    }

    /**
      Get ToolTipKeys
    */
    static
    QStringList toolTipKeys()
    {
      return self()->mToolTipKeys;
    }

  protected:
    KNetworkManagerServicePrefs(const QString& arg);
    friend class KNetworkManagerServicePrefsHelper;


    // General
    QStringList mConnections;
    int mSecretStorageMode;
    bool mAutostart;
    int mInterfaceNamingStyle;
    int mNetworkSpeedUnit;
    bool mShowAdvancedSettings;
    int mAskForGsmPin;

    // SystemTray
    uint mIconCount;
    uint mIconTypes[5];
    QStringList mToolTipKeys;

  private:
};

#endif

