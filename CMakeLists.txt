cmake_minimum_required (VERSION 3.11)
project (photon-libtcmu CXX)
set(VERSION 1.5.4)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/CMake")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fpic -fpermissive")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpic -fpermissive")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED on)


find_package(nl REQUIRED)
find_package(photon REQUIRED)

# Stuff for building the shared library
add_library(libtcmu SHARED
  configfs.cpp
  api.cpp
  libtcmu.cpp
  scsi.cpp
)
set_target_properties(libtcmu
  PROPERTIES
  VERSION 2.2
  SOVERSION "2"
)
target_include_directories(libtcmu
  PUBLIC ${LIBNL_INCLUDE_DIR}
  PUBLIC ${PHOTON_INCLUDE_DIR}
)
target_link_libraries(libtcmu
  ${LIBNL_LIB}
  ${LIBNL_GENL_LIB}
  photon
)
install(TARGETS libtcmu LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Stuff for building the static library
add_library(libtcmu_static
  configfs.cpp
  api.cpp
  libtcmu.cpp
  scsi.cpp
)
target_include_directories(libtcmu_static
  PUBLIC ${LIBNL_INCLUDE_DIR}
  PUBLIC ${PHOTON_INCLUDE_DIR}
)
target_link_libraries(libtcmu_static
  ${LIBNL_LIB}
  ${LIBNL_GENL_LIB}
  photon
)