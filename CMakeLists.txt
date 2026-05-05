cmake_minimum_required(VERSION 3.15)
project(chaco256 VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Options
option(CHACO256_BUILD_EXAMPLES "Build examples" OFF)
option(CHACO256_BUILD_TESTS "Build tests" OFF)

# Find Rust and Cargo
find_program(CARGO cargo REQUIRED)
find_program(RUSTC rustc REQUIRED)

# Determine build type for Cargo
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_BUILD_TYPE "debug")
    set(CARGO_BUILD_FLAG "")
else()
    set(CARGO_BUILD_TYPE "release")
    set(CARGO_BUILD_FLAG "--release")
endif()

# Build Rust library
set(RUST_LIB_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust")
set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/target")

if(WIN32)
    set(RUST_LIB_NAME "chaco256.dll")
    set(RUST_LIB_PATH "${RUST_TARGET_DIR}/${CARGO_BUILD_TYPE}/${RUST_LIB_NAME}")
elseif(APPLE)
    set(RUST_LIB_NAME "libchaco256.dylib")
    set(RUST_LIB_PATH "${RUST_TARGET_DIR}/${CARGO_BUILD_TYPE}/${RUST_LIB_NAME}")
else()
    set(RUST_LIB_NAME "libchaco256.so")
    set(RUST_LIB_PATH "${RUST_TARGET_DIR}/${CARGO_BUILD_TYPE}/${RUST_LIB_NAME}")
endif()

# Custom command to build Rust library
add_custom_command(
    OUTPUT ${RUST_LIB_PATH}
    COMMAND ${CARGO} build ${CARGO_BUILD_FLAG} --features ffi
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building Rust library with Cargo"
)

add_custom_target(rust_build ALL DEPENDS ${RUST_LIB_PATH})

# Create imported library
add_library(chaco256 SHARED IMPORTED GLOBAL)
add_dependencies(chaco256 rust_build)

set_target_properties(chaco256 PROPERTIES
    IMPORTED_LOCATION ${RUST_LIB_PATH}
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/bindings"
)

# Install
install(FILES ${RUST_LIB_PATH} DESTINATION lib)
install(FILES bindings/chaco256.h DESTINATION include)

# Examples
if(CHACO256_BUILD_EXAMPLES)
    add_executable(example_c bindings/examples/example.c)
    target_link_libraries(example_c PRIVATE chaco256)

    add_executable(example_cpp bindings/examples/example.cpp)
    target_link_libraries(example_cpp PRIVATE chaco256)
endif()

# Package config
include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/chaco256-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/chaco256-config.cmake"
    INSTALL_DESTINATION lib/cmake/chaco256
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/chaco256-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/chaco256-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/chaco256-config-version.cmake"
    DESTINATION lib/cmake/chaco256
)
