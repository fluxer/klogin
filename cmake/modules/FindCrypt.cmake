# - Try to find crypt
# Once done this will define
#
#  CRYPT_FOUND - system has crypt
#  CRYPT_INCLUDES - the crypt include directory
#  CRYPT_LIBRARIES - The libraries needed to use crypt
#
# Copyright (c) 2018, Ivailo Monev, <xakepa10@gmail.com>
# Redistribution and use is allowed according to the terms of the BSD license.

if(CRYPT_INCLUDES AND CRYPT_LIBRARIES)
    set(CRYPT_FIND_QUIETLY TRUE)
endif()

# crypt does not provide pkg-config files

find_path(CRYPT_INCLUDES
    NAMES crypt.h
    HINTS $ENV{CRYPTDIR}/include
)

find_library(CRYPT_LIBRARIES
    NAMES crypt
    HINTS $ENV{CRYPTDIR}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Crypt
    REQUIRED_VARS CRYPT_INCLUDES CRYPT_LIBRARIES
)

mark_as_advanced(CRYPT_INCLUDES CRYPT_LIBRARIES)
