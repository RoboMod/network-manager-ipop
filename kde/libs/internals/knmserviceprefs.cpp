// This file is generated by kconfig_compiler from knmserviceprefs.kcfg.
// All changes you do to this file will be lost.

#include "knmserviceprefs.h"

#include <kglobal.h>
#include <QtCore/QFile>

#include <kdebug.h>

class KNetworkManagerServicePrefsHelper
{
  public:
    KNetworkManagerServicePrefsHelper() : q(0) {}
    ~KNetworkManagerServicePrefsHelper() { delete q; }
    KNetworkManagerServicePrefs *q;
};
K_GLOBAL_STATIC(KNetworkManagerServicePrefsHelper, s_globalKNetworkManagerServicePrefs)
KNetworkManagerServicePrefs *KNetworkManagerServicePrefs::self()
{
  if (!s_globalKNetworkManagerServicePrefs->q)
     kFatal() << "you need to call KNetworkManagerServicePrefs::instance before using";
  return s_globalKNetworkManagerServicePrefs->q;
}

void KNetworkManagerServicePrefs::instance(const QString& cfgfilename)
{
  if (s_globalKNetworkManagerServicePrefs->q) {
     kDebug() << "KNetworkManagerServicePrefs::instance called after the first use - ignoring";
     return;
  }
  new KNetworkManagerServicePrefs(cfgfilename);
  s_globalKNetworkManagerServicePrefs->q->readConfig();
}

KNetworkManagerServicePrefs::KNetworkManagerServicePrefs(  const QString& config  )
  : KConfigSkeleton( config )
{
  Q_ASSERT(!s_globalKNetworkManagerServicePrefs->q);
  s_globalKNetworkManagerServicePrefs->q = this;
  setCurrentGroup( QLatin1String( "General" ) );

  KConfigSkeleton::ItemStringList  *itemConnections;
  itemConnections = new KConfigSkeleton::ItemStringList( currentGroup(), QLatin1String( "Connections" ), mConnections );
  addItem( itemConnections, QLatin1String( "Connections" ) );
  QList<KConfigSkeleton::ItemEnum::Choice2> valuesSecretStorageMode;
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("DontStore");
    valuesSecretStorageMode.append( choice );
  }
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("PlainText");
    valuesSecretStorageMode.append( choice );
  }
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("Secure");
    valuesSecretStorageMode.append( choice );
  }
  KConfigSkeleton::ItemEnum  *itemSecretStorageMode;
  itemSecretStorageMode = new KConfigSkeleton::ItemEnum( currentGroup(), QLatin1String( "SecretStorageMode" ), mSecretStorageMode, valuesSecretStorageMode, (KWallet::Wallet::isEnabled() ? SecretStorage::Secure : SecretStorage::PlainText) );
  addItem( itemSecretStorageMode, QLatin1String( "SecretStorageMode" ) );
  KConfigSkeleton::ItemBool  *itemAutostart;
  itemAutostart = new KConfigSkeleton::ItemBool( currentGroup(), QLatin1String( "Autostart" ), mAutostart, true );
  addItem( itemAutostart, QLatin1String( "Autostart" ) );
  QList<KConfigSkeleton::ItemEnum::Choice2> valuesInterfaceNamingStyle;
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("DescriptiveNames");
    valuesInterfaceNamingStyle.append( choice );
  }
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("SystemNames");
    valuesInterfaceNamingStyle.append( choice );
  }
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("VendorProductNames");
    valuesInterfaceNamingStyle.append( choice );
  }
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("TypeNames");
    valuesInterfaceNamingStyle.append( choice );
  }
  KConfigSkeleton::ItemEnum  *itemInterfaceNamingStyle;
  itemInterfaceNamingStyle = new KConfigSkeleton::ItemEnum( currentGroup(), QLatin1String( "InterfaceNamingStyle" ), mInterfaceNamingStyle, valuesInterfaceNamingStyle );
  addItem( itemInterfaceNamingStyle, QLatin1String( "InterfaceNamingStyle" ) );
  QList<KConfigSkeleton::ItemEnum::Choice2> valuesNetworkSpeedUnit;
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("KBytes_s");
    valuesNetworkSpeedUnit.append( choice );
  }
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("KBits_s");
    valuesNetworkSpeedUnit.append( choice );
  }
  KConfigSkeleton::ItemEnum  *itemNetworkSpeedUnit;
  itemNetworkSpeedUnit = new KConfigSkeleton::ItemEnum( currentGroup(), QLatin1String( "NetworkSpeedUnit" ), mNetworkSpeedUnit, valuesNetworkSpeedUnit );
  addItem( itemNetworkSpeedUnit, QLatin1String( "NetworkSpeedUnit" ) );
  KConfigSkeleton::ItemBool  *itemShowAdvancedSettings;
  itemShowAdvancedSettings = new KConfigSkeleton::ItemBool( currentGroup(), QLatin1String( "ShowAdvancedSettings" ), mShowAdvancedSettings, false );
  addItem( itemShowAdvancedSettings, QLatin1String( "ShowAdvancedSettings" ) );
  QList<KConfigSkeleton::ItemEnum::Choice2> valuesAskForGsmPin;
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("OnModemDetection");
    valuesAskForGsmPin.append( choice );
  }
  {
    KConfigSkeleton::ItemEnum::Choice2 choice;
    choice.name = QLatin1String("WhenActivatingConnection");
    valuesAskForGsmPin.append( choice );
  }
  KConfigSkeleton::ItemEnum  *itemAskForGsmPin;
  itemAskForGsmPin = new KConfigSkeleton::ItemEnum( currentGroup(), QLatin1String( "AskForGsmPin" ), mAskForGsmPin, valuesAskForGsmPin );
  addItem( itemAskForGsmPin, QLatin1String( "AskForGsmPin" ) );

  setCurrentGroup( QLatin1String( "SystemTray" ) );

  KConfigSkeleton::ItemUInt  *itemIconCount;
  itemIconCount = new KConfigSkeleton::ItemUInt( currentGroup(), QLatin1String( "IconCount" ), mIconCount, 1 );
  itemIconCount->setMinValue(1);
  itemIconCount->setMaxValue(5);
  addItem( itemIconCount, QLatin1String( "IconCount" ) );
  KConfigSkeleton::ItemUInt  *itemIconTypes[5];
  itemIconTypes[0] = new KConfigSkeleton::ItemUInt( currentGroup(), QLatin1String( "IconTypes_0" ), mIconTypes[0], 31 );
  addItem( itemIconTypes[0], QLatin1String( "IconTypes0" ) );
  itemIconTypes[1] = new KConfigSkeleton::ItemUInt( currentGroup(), QLatin1String( "IconTypes_1" ), mIconTypes[1], 0 );
  addItem( itemIconTypes[1], QLatin1String( "IconTypes1" ) );
  itemIconTypes[2] = new KConfigSkeleton::ItemUInt( currentGroup(), QLatin1String( "IconTypes_2" ), mIconTypes[2], 0 );
  addItem( itemIconTypes[2], QLatin1String( "IconTypes2" ) );
  itemIconTypes[3] = new KConfigSkeleton::ItemUInt( currentGroup(), QLatin1String( "IconTypes_3" ), mIconTypes[3], 0 );
  addItem( itemIconTypes[3], QLatin1String( "IconTypes3" ) );
  itemIconTypes[4] = new KConfigSkeleton::ItemUInt( currentGroup(), QLatin1String( "IconTypes_4" ), mIconTypes[4], 0 );
  addItem( itemIconTypes[4], QLatin1String( "IconTypes4" ) );
  QStringList defaultToolTipKeys;
  defaultToolTipKeys.append( QString::fromUtf8( "interface:type" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "interface:name" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "interface:hardwareaddress" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "interface:driver" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "interface:status" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "interface:bitrate" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "ipv4:address" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "ipv4:nameservers" ) );
  defaultToolTipKeys.append( QString::fromUtf8( "ipv4:domains" ) );

  KConfigSkeleton::ItemStringList  *itemToolTipKeys;
  itemToolTipKeys = new KConfigSkeleton::ItemStringList( currentGroup(), QLatin1String( "ToolTipKeys" ), mToolTipKeys, defaultToolTipKeys );
  addItem( itemToolTipKeys, QLatin1String( "ToolTipKeys" ) );
}

KNetworkManagerServicePrefs::~KNetworkManagerServicePrefs()
{
  if (!s_globalKNetworkManagerServicePrefs.isDestroyed()) {
    s_globalKNetworkManagerServicePrefs->q = 0;
  }
}

