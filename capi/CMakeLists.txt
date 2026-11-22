# snmpify for C and C++ with CMake (Linux, macOS, Windows).
#
# In your project, either use an installed / prebuilt snmpify:
#   find_package(snmpify 0.1 REQUIRED)
#   target_link_libraries(app PRIVATE snmpify::snmpify)
# or build it from source as part of your project:
#   add_subdirectory(path/to/snmpify/capi snmpify)
#   target_link_libraries(app PRIVATE snmpify::snmpify)
#
# Builds the Rust library with cargo (stable Rust). Options:
#   SNMPIFY_STATIC    snmpify::snmpify links the static library (default OFF)
#   SNMPIFY_TESTS     build the C/C++ tests and examples, run them with ctest
#   SNMPIFY_EXAMPLES  build the examples
# `cmake --install` installs the headers, both libraries, the CMake package
# (lib/cmake/snmpify) and the pkg-config file (lib/pkgconfig/snmpify.pc).
cmake_minimum_required(VERSION 3.16)
project(snmpify_c VERSION 0.1.0 LANGUAGES C CXX)

option(SNMPIFY_STATIC "Link snmpify::snmpify statically" OFF)
option(SNMPIFY_TESTS "Build the snmpify C/C++ tests (ctest)" OFF)
option(SNMPIFY_EXAMPLES "Build the snmpify C/C++ examples" ${SNMPIFY_TESTS})

find_program(CARGO cargo HINTS $ENV{HOME}/.cargo/bin $ENV{USERPROFILE}/.cargo/bin REQUIRED)
include(GNUInstallDirs)

set(_root ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(_target_dir ${CMAKE_CURRENT_BINARY_DIR}/cargo)
set(_out ${_target_dir}/release)

# Library files and the system libraries the Rust static library needs
# (`rustc --print native-static-libs`).
if(WIN32)
  set(_shared ${_out}/snmpify.dll)
  set(_implib ${_out}/snmpify.dll.lib)
  set(_static ${_out}/snmpify.lib)
  set(SNMPIFY_STATIC_LIBS kernel32 advapi32 ntdll userenv ws2_32 dbghelp bcrypt)
elseif(APPLE)
  set(_shared ${_out}/libsnmpify.dylib)
  set(_static ${_out}/libsnmpify.a)
  set(SNMPIFY_STATIC_LIBS System c m)
else()
  set(_shared ${_out}/libsnmpify.so)
  set(_static ${_out}/libsnmpify.a)
  set(SNMPIFY_STATIC_LIBS gcc_s util rt pthread m dl c)
endif()

file(GLOB_RECURSE _sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.rs ${_root}/src/*.rs)

add_custom_command(
  OUTPUT ${_shared} ${_static} ${_implib}
  COMMAND ${CARGO} build --release -p snmpify-c --target-dir ${_target_dir}
  WORKING_DIRECTORY ${_root}
  DEPENDS ${_sources} ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml ${CMAKE_CURRENT_SOURCE_DIR}/build.rs
          ${_root}/Cargo.toml
  COMMENT "Building snmpify (cargo)"
  USES_TERMINAL)
add_custom_target(snmpify_cargo ALL DEPENDS ${_shared} ${_static})

add_library(snmpify_shared SHARED IMPORTED GLOBAL)
set_target_properties(snmpify_shared PROPERTIES
  IMPORTED_LOCATION ${_shared}
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(WIN32)
  set_target_properties(snmpify_shared PROPERTIES IMPORTED_IMPLIB ${_implib})
else()
  get_filename_component(_soname ${_shared} NAME)
  set_target_properties(snmpify_shared PROPERTIES IMPORTED_SONAME ${_soname}
    INTERFACE_LINK_OPTIONS "LINKER:-rpath,${_out}")
endif()
add_dependencies(snmpify_shared snmpify_cargo)

add_library(snmpify_static STATIC IMPORTED GLOBAL)
set_target_properties(snmpify_static PROPERTIES
  IMPORTED_LOCATION ${_static}
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include
  INTERFACE_LINK_LIBRARIES "${SNMPIFY_STATIC_LIBS}")
add_dependencies(snmpify_static snmpify_cargo)

if(SNMPIFY_STATIC)
  add_library(snmpify::snmpify ALIAS snmpify_static)
else()
  add_library(snmpify::snmpify ALIAS snmpify_shared)
endif()
add_library(snmpify::shared ALIAS snmpify_shared)
add_library(snmpify::static ALIAS snmpify_static)

# The shared library file, e.g. to copy next to an executable.
set(SNMPIFY_SHARED_LIBRARY ${_shared} CACHE INTERNAL "")

# ---------------------------------------------------------------------------
# Install: headers, libraries, CMake package, pkg-config
# ---------------------------------------------------------------------------
install(FILES include/snmpify.h include/snmpify.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(WIN32)
  install(FILES ${_shared} DESTINATION ${CMAKE_INSTALL_BINDIR})
  install(FILES ${_implib} ${_static} DESTINATION ${CMAKE_INSTALL_LIBDIR})
else()
  install(FILES ${_shared} ${_static} DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

get_filename_component(SNMPIFY_SHARED_NAME ${_shared} NAME)
get_filename_component(SNMPIFY_STATIC_NAME ${_static} NAME)
if(WIN32)
  get_filename_component(SNMPIFY_IMPLIB_NAME ${_implib} NAME)
endif()
include(CMakePackageConfigHelpers)
set(SNMPIFY_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})
set(SNMPIFY_INSTALL_BINDIR ${CMAKE_INSTALL_BINDIR})
set(SNMPIFY_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR})
configure_package_config_file(cmake/snmpifyConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/snmpifyConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snmpify
  PATH_VARS SNMPIFY_INSTALL_LIBDIR SNMPIFY_INSTALL_BINDIR SNMPIFY_INSTALL_INCLUDEDIR)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/snmpifyConfigVersion.cmake
  COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/snmpifyConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/snmpifyConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snmpify)

if(NOT WIN32)
  string(REPLACE ";" " -l" _pc_static "-l${SNMPIFY_STATIC_LIBS}")
  set(SNMPIFY_PC_LIBDIR ${CMAKE_INSTALL_LIBDIR})
  set(SNMPIFY_PC_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR})
  set(SNMPIFY_PC_LIBS_PRIVATE ${_pc_static})
  # Relocatable: the prefix relative to the installed .pc file.
  file(RELATIVE_PATH SNMPIFY_PC_PREFIX_REL ${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig ${CMAKE_INSTALL_PREFIX})
  configure_file(cmake/snmpify.pc.in ${CMAKE_CURRENT_BINARY_DIR}/snmpify.pc @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/snmpify.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()

# ---------------------------------------------------------------------------
# Examples and tests
# ---------------------------------------------------------------------------
function(snmpify_warnings t)
  if(MSVC)
    target_compile_options(${t} PRIVATE /W3 /WX)
    target_compile_definitions(${t} PRIVATE _CRT_SECURE_NO_WARNINGS)
  else()
    target_compile_options(${t} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endfunction()

# Windows finds DLLs next to the executable.
function(snmpify_copy_dll t)
  if(WIN32)
    add_custom_command(TARGET ${t} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_shared} $<TARGET_FILE_DIR:${t}>)
  endif()
endfunction()

if(SNMPIFY_EXAMPLES)
  add_executable(snmpify_get examples/get.c)
  add_executable(snmpify_walk examples/walk.cpp)
  add_executable(snmpify_trapd examples/trapd.c)
  foreach(t snmpify_get snmpify_walk snmpify_trapd)
    target_link_libraries(${t} PRIVATE snmpify::snmpify)
    snmpify_warnings(${t})
    snmpify_copy_dll(${t})
  endforeach()
  set_target_properties(snmpify_get snmpify_trapd PROPERTIES C_STANDARD 99)
  set_target_properties(snmpify_walk PROPERTIES CXX_STANDARD 17)
endif()

if(SNMPIFY_TESTS)
  enable_testing()
  add_executable(snmpify_test_c tests/test.c)
  add_executable(snmpify_test_c_static tests/test.c)
  add_executable(snmpify_test_cpp tests/test.cpp)
  target_link_libraries(snmpify_test_c PRIVATE snmpify::shared)
  target_link_libraries(snmpify_test_c_static PRIVATE snmpify::static)
  target_link_libraries(snmpify_test_cpp PRIVATE snmpify::snmpify)
  set_target_properties(snmpify_test_c snmpify_test_c_static PROPERTIES C_STANDARD 99
                        C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  set_target_properties(snmpify_test_cpp PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
  foreach(t snmpify_test_c snmpify_test_c_static snmpify_test_cpp)
    snmpify_warnings(${t})
    snmpify_copy_dll(${t})
    add_test(NAME ${t} COMMAND ${t})
  endforeach()
  # The examples against an agent of the C++ test… simplest: usage errors.
  add_test(NAME snmpify_example_usage COMMAND snmpify_get)
  set_tests_properties(snmpify_example_usage PROPERTIES WILL_FAIL ON)
endif()
