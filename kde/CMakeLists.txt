project(networkmanagement_ipop)
cmake_minimum_required(VERSION 2.8)
set(MINIMUM_NM_VERSION_REQUIRED "0.9.6")

find_package(KDE4 "4.9.0" REQUIRED)
find_package(KDE4 REQUIRED)

include(KDE4Defaults)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR} ${CMAKE_MODULE_PATH})

pkg_check_modules(NETWORKMANAGERQT REQUIRED NetworkManagerQt)
if(NOT NETWORKMANAGERQT_FOUND)
    message(FATAL_ERROR "ERROR: NetworkManagerQt not found. http://projects.kde.org/search?q=networkmanager&scope=all&all_words=1&projects=1&submit=Submit")
endif(NOT NETWORKMANAGERQT_FOUND)

#find_package(QJson REQUIRED)
pkg_check_modules(QJSON REQUIRED QJson)
if(NOT QJSON_FOUND)
    message(FATAL ERROR "ERROR: QJson not found.")
endif(NOT QJSON_FOUND)

include_directories(${KDE4_INCLUDES} ${NETWORKMANAGERQT_INCLUDE_DIRS} ${QJSON_INCLUDE_DIRS} ${CMAKE_INCLUDE_PATH})
link_directories(${NETWORKMANAGERQT_LIBRARY_DIRS} ${QJSON_LIBRARY_DIRS} ${CMAKE_LIBRARY_PATH})

find_package(NetworkManager ${MINIMUM_NM_VERSION_REQUIRED})

if(NETWORKMANAGER_FOUND)
    PKG_SEARCH_MODULE( NM-UTIL libnm-util )
    if(NOT NM-UTIL_FOUND)
        message(FATAL_ERROR "Could NOT find libnm-util, check FindPkgConfig output above!")
    endif(NOT NM-UTIL_FOUND)

    if(${NETWORKMANAGER_VERSION} VERSION_GREATER ${MINIMUM_NM_VERSION_REQUIRED} OR
        ${NETWORKMANAGER_VERSION} VERSION_EQUAL ${MINIMUM_NM_VERSION_REQUIRED})
        set(NM_0_9 TRUE)
        add_definitions(-DMINIMUM_NM_VERSION_REQUIRED=\\"${MINIMUM_NM_VERSION_REQUIRED}\\")
        include_directories(
           ${NETWORKMANAGER_INCLUDE_DIRS}
           ${NM-UTIL_INCLUDE_DIRS}
           ${CMAKE_CURRENT_BUILD_DIR}
           solidcontrolfuture/libs
           ${KDE4_INCLUDE_DIR}/solid/control
        )
        link_directories(${NM-UTIL_LIBRARY_DIRS})

        add_subdirectory(solidcontrolfuture)
        add_subdirectory(settings)
        add_subdirectory(backends)
        add_subdirectory(libs)
        add_subdirectory(vpnplugins)

        install( FILES networkmanagement.notifyrc DESTINATION ${DATA_INSTALL_DIR}/networkmanagement )
    else()
        message(FATAL_ERROR "ERROR: NetworkManager version '${NETWORKMANAGER_VERSION}' does not match minimum required (${MINIMUM_NM_VERSION_REQUIRED})")
    endif()
else(NETWORKMANAGER_FOUND)
    message(FATAL_ERROR "ERROR: NetworkManager headers >= ${MINIMUM_NM_VERSION_REQUIRED} not installed. http://projects.gnome.org/NetworkManager/")
endif(NETWORKMANAGER_FOUND)
