cmake_minimum_required(VERSION 3.25)

# Determine NDK path based on environment variable or default location
# This must be set before project() to properly configure cross-compilation
# Prioritize explicit ANDROID_NDK_PATH cache variable, then default paths
if(NOT DEFINED ANDROID_NDK_PATH)
    if(CMAKE_HOST_WIN32)
        set(ANDROID_NDK_PATH "$ENV{USERPROFILE}/android-ndk-r23b")
    else()
        set(ANDROID_NDK_PATH "$ENV{HOME}/android-ndk-r23b")
    endif()
    # Only use ANDROID_NDK_HOME if the default path doesn't exist
    if(DEFINED ENV{ANDROID_NDK_HOME} AND NOT EXISTS "${ANDROID_NDK_PATH}")
        set(ANDROID_NDK_PATH "$ENV{ANDROID_NDK_HOME}")
    endif()
endif()

# Determine host platform for prebuilt tools
if(CMAKE_HOST_WIN32)
    set(HOST_TAG "windows-x86_64")
    set(EXE_SUFFIX ".exe")
    set(CMD_SUFFIX ".cmd")
else()
    set(HOST_TAG "linux-x86_64")
    set(EXE_SUFFIX "")
    set(CMD_SUFFIX "")
endif()

set(TOOLCHAIN "${ANDROID_NDK_PATH}/toolchains/llvm/prebuilt/${HOST_TAG}")

# Set compilers before project() to ensure cross-compilation is properly configured
set(CMAKE_C_COMPILER "${TOOLCHAIN}/bin/x86_64-linux-android22-clang${CMD_SUFFIX}")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN}/bin/x86_64-linux-android22-clang++${CMD_SUFFIX}")
set(C_COMPILER "${TOOLCHAIN}/bin/clang${EXE_SUFFIX}")

# Set system name for cross-compilation
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 22)
set(CMAKE_ANDROID_ARCH_ABI x86_64)

project(wrapper)
include(ExternalProject)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

set(CMDLINE_SOURCE cmdline.c)
set(HANDLE_SOURCE main.cpp)
set(CJSON_SOURCE cjson/cjson.c)
set(MAIN_SOURCE main.c)
set(WRAPPER_SOURCE wrapper.c)

add_library(cmdline_object OBJECT ${CMDLINE_SOURCE})
add_library(handle_object OBJECT ${HANDLE_SOURCE})
add_library(cjson_object OBJECT ${CJSON_SOURCE})

add_executable(main ${MAIN_SOURCE} $<TARGET_OBJECTS:cmdline_object> $<TARGET_OBJECTS:handle_object> $<TARGET_OBJECTS:cjson_object>)

set_target_properties(main PROPERTIES 
    COMPILE_DEFINITIONS "MyRelease"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/rootfs/system/bin"
)

find_library(ANDROIDAPPMUSIC_LIB androidappmusic PATHS ${CMAKE_SOURCE_DIR}/rootfs/system/lib64 NO_DEFAULT_PATH)
find_library(STORESERVICESCORE_LIB storeservicescore PATHS ${CMAKE_SOURCE_DIR}/rootfs/system/lib64 NO_DEFAULT_PATH)
find_library(MEDIAPLATFORM_LIB mediaplatform PATHS ${CMAKE_SOURCE_DIR}/rootfs/system/lib64 NO_DEFAULT_PATH)
find_library(CXX_SHARED_LIB c++_shared PATHS ${CMAKE_SOURCE_DIR}/rootfs/system/lib64 NO_DEFAULT_PATH)
find_library(CURL_SHARED_LIB curl PATHS ${CMAKE_SOURCE_DIR}/rootfs/system/lib64 NO_DEFAULT_PATH)
find_library(LOG_SHARED_LIB log PATHS ${CMAKE_SOURCE_DIR}/rootfs/system/lib64 NO_DEFAULT_PATH)

# Link libraries
target_link_libraries(main
    ${CXX_SHARED_LIB}
    ${ANDROIDAPPMUSIC_LIB}
    ${STORESERVICESCORE_LIB}
    ${MEDIAPLATFORM_LIB}
)

get_target_property(MAIN_COMPILE_DEFINITIONS main COMPILE_DEFINITIONS)
if(NOT "MyRelease" IN_LIST MAIN_COMPILE_DEFINITIONS)
    target_link_libraries(main
        ${LOG_SHARED_LIB}
        ${CURL_SHARED_LIB}
    )
    set(CMAKE_C_FLAGS "-Werror -g")
    set(CMAKE_CXX_FLAGS "-Werror -g")
else()
    set(CMAKE_C_FLAGS "-Wall -Werror")
    set(CMAKE_CXX_FLAGS "-Wall -Werror")
endif()

link_directories(${CMAKE_SOURCE_DIR}/rootfs/system/lib64)

# Determine wrapper output name based on host platform
if(CMAKE_HOST_WIN32)
    set(WRAPPER_OUTPUT "wrapper.exe")
else()
    set(WRAPPER_OUTPUT "wrapper")
endif()

ExternalProject_Add(
    wrapper
    PREFIX ${CMAKE_BINARY_DIR}
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${C_COMPILER} -O3 -Wall -o ${WRAPPER_OUTPUT} ${WRAPPER_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/cmdline.c
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND ""
    DEPENDS main
)