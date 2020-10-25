cmake_minimum_required(VERSION 3.0.3 FATAL_ERROR)

project(klogin C CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
set(CMAKE_AUTOMOC TRUE)
set(CMAKE_AUTOUIC TRUE)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# required because Katie does
if(NOT CMAKE_VERSION VERSION_LESS "3.1.0")
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_STANDARD 11)
endif()

if(NOT CMAKE_VERSION VERSION_LESS "3.3.0")
    cmake_policy(SET CMP0063 NEW)
endif()

include(FeatureSummary)
include(GNUInstallDirs)

find_package(Katie)
set_package_properties(Katie PROPERTIES
    PURPOSE "The building block of this project"
    DESCRIPTION "C++ toolkit derived from the Qt 4.8 framework"
    URL "http://fluxer.github.io/katie/"
    TYPE REQUIRED
)

find_package(Crypt)
set_package_properties(Crypt PROPERTIES
    PURPOSE "Login support"
    DESCRIPTION "library provided by standard C libraries"
    URL ""
    TYPE REQUIRED
)

add_definitions(${QT_DEFINITIONS})

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${QT_INCLUDES}
    ${CMAKE_SOURCE_DIR}/src
)

add_executable(klogin ${CMAKE_SOURCE_DIR}/src/klogin.cpp)
target_link_libraries(klogin
    ${QT_QTCORE_LIBRARY}
    ${QT_QTGUI_LIBRARY}
    ${CRYPT_LIBRARIES}
)

install(
    TARGETS klogin
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
