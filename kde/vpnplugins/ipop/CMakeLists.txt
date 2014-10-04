include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libs/ui)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libs)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libs/internals)

set(ipop_SRCS
   ipop.cpp
   ipopwidget.cpp
   ipopauth.cpp
   )

kde4_add_ui_files(ipop_SRCS ipopprop.ui)

kde4_add_plugin(networkmanagement_ipopui ${ipop_SRCS})

target_link_libraries(networkmanagement_ipopui solidcontrolnm09 ${KDE4_KIO_LIBS} knmui knminternals )

install(TARGETS networkmanagement_ipopui  DESTINATION ${PLUGIN_INSTALL_DIR})

install( FILES networkmanagement_ipopui.desktop  DESTINATION ${SERVICES_INSTALL_DIR})
