include(FetchContent)
set(FETCHCONTENT_QUIET false)

FetchContent_Declare(
  photon
  GIT_REPOSITORY https://github.com/alibaba/PhotonLibOS.git
  GIT_TAG main
)
FetchContent_GetProperties(photon)
if (NOT photon_POPULATED)
  FetchContent_Populate(photon)
  add_subdirectory(${photon_SOURCE_DIR})
endif()
set(PHOTON_INCLUDE_DIR ${photon_SOURCE_DIR}/include/)
