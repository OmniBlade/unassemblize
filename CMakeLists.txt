cmake_minimum_required(VERSION 3.24)

# Use packagename_ROOT for FindPackage.
if(POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif()

# Disable default MSVC warning level so we can set it ourselves.
if(POLICY CMP0092)
    cmake_policy(SET CMP0092 NEW)
endif()

# Disable default MSVC runtime hardcoding.
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

project(unassemblize LANGUAGES C CXX)

# Set up a format target to do automated clang format checking.
find_package(ClangFormat)
include(ClangFormat)

if(WIN32 OR "${CMAKE_SYSTEM}" MATCHES "Windows")
    set(WINDOWS TRUE)
endif()

include(FetchContent)

FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        1ba75aeefae37094c7be8eba07ff81d4fe0f1f20
)
set(ZYDIS_BUILD_EXAMPLES OFF)
set(ZYDIS_FEATURE_ENCODER OFF)
FetchContent_MakeAvailable(zydis)

FetchContent_Declare(
    lief
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG        2d9855fc7f9d4ce6325245f8b75c98eb7663db60
)
set(LEIF_EXAMPLES OFF)
set(LEIF_INSTALL OFF)
set(LIEF_C_API OFF)
set(LIEF_PYTHON_API OFF)
set(LIEF_TESTS OFF)
FetchContent_MakeAvailable(lief)

set(GIT_PRE_CONFIGURE_FILE "gitinfo.cpp.in")
set(GIT_POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/gitinfo.cpp")
include(GitWatcher)

add_executable(unassemblize)

target_sources(unassemblize PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/gitinfo.cpp
    gitinfo.h
    executable.cpp
    executable.h
    function.cpp
    function.h
    main.cpp
    symbols.cpp
    symbols.h)
target_link_libraries(unassemblize PRIVATE Zydis LIEF::LIEF)
target_include_directories(unassemblize PRIVATE .)

if(WINDOWS)
    target_sources(unassemblize PRIVATE wincompat/getopt.c wincompat/getopt.h wincompat/strings.h)
    target_include_directories(unassemblize PRIVATE wincompat)
endif()
