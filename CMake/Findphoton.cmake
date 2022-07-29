include(FetchContent)
set(FETCHCONTENT_QUIET false)

FetchContent_Declare(
  photon
  GIT_REPOSITORY https://github.com/alibaba/PhotonLibOS.git
  GIT_TAG v0.1.0
)
FetchContent_MakeAvailable(photon)
set(PHOTON_INCLUDE_DIR ${photon_SOURCE_DIR}/include/)
