cmake_minimum_required(VERSION 3.20)
project(hello_multilang LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_language(ASM)

if(NOT DEFINED TARGET_ARCH)
    message(FATAL_ERROR "TARGET_ARCH is not set. Pass -DTARGET_ARCH=<arch> from build.sh")
endif()

message(STATUS "Configuring for TARGET_ARCH=${TARGET_ARCH}")
message(STATUS "CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}")

# ------------------------------------------------------------
# Native C / C++
# ------------------------------------------------------------
add_executable(hello_c hello.c)
add_executable(hello_cpp hello.cpp)

# The x86/x86_64 toolchain files already choose the correct compiler.
# Only RISC-V needs explicit march/mabi flags here.
if(TARGET_ARCH STREQUAL "rv32")
    target_compile_options(hello_c PRIVATE -march=rv32gc -mabi=ilp32d)
    target_link_options(hello_c PRIVATE -march=rv32gc -mabi=ilp32d)

    target_compile_options(hello_cpp PRIVATE -march=rv32gc -mabi=ilp32d)
    target_link_options(hello_cpp PRIVATE -march=rv32gc -mabi=ilp32d)
elseif(TARGET_ARCH STREQUAL "rv64")
    target_compile_options(hello_c PRIVATE -march=rv64gc -mabi=lp64d)
    target_link_options(hello_c PRIVATE -march=rv64gc -mabi=lp64d)

    target_compile_options(hello_cpp PRIVATE -march=rv64gc -mabi=lp64d)
    target_link_options(hello_cpp PRIVATE -march=rv64gc -mabi=lp64d)
endif()

# ------------------------------------------------------------
# Assembly
# Raw syscall _start binaries: no libc, no PIE
# ------------------------------------------------------------
set(HELLO_ASM_SOURCE "")
set(HELLO_ASM_COMPILE_FLAGS "")
set(HELLO_ASM_LINK_FLAGS "-nostdlib -no-pie")

if(TARGET_ARCH STREQUAL "x86")
    set(HELLO_ASM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/asm/hello_x86.S")
elseif(TARGET_ARCH STREQUAL "x86_64")
    set(HELLO_ASM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/asm/hello_x86_64.S")
elseif(TARGET_ARCH STREQUAL "arm32")
    set(HELLO_ASM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/asm/hello_arm32.S")
elseif(TARGET_ARCH STREQUAL "aarch64")
    set(HELLO_ASM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/asm/hello_aarch64.S")
elseif(TARGET_ARCH STREQUAL "rv32")
    set(HELLO_ASM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/asm/hello_rv32.S")
    set(HELLO_ASM_COMPILE_FLAGS "-march=rv32gc -mabi=ilp32d")
    string(APPEND HELLO_ASM_LINK_FLAGS " -march=rv32gc -mabi=ilp32d")
elseif(TARGET_ARCH STREQUAL "rv64")
    set(HELLO_ASM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/asm/hello_rv64.S")
    set(HELLO_ASM_COMPILE_FLAGS "-march=rv64gc -mabi=lp64d")
    string(APPEND HELLO_ASM_LINK_FLAGS " -march=rv64gc -mabi=lp64d")
else()
    message(WARNING "Unsupported TARGET_ARCH for assembly: ${TARGET_ARCH}")
endif()

if(HELLO_ASM_SOURCE AND EXISTS "${HELLO_ASM_SOURCE}")
    add_executable(hello_asm "${HELLO_ASM_SOURCE}")
    set_property(TARGET hello_asm PROPERTY LINKER_LANGUAGE C)

    if(HELLO_ASM_COMPILE_FLAGS)
        separate_arguments(HELLO_ASM_COMPILE_FLAGS_LIST NATIVE_COMMAND "${HELLO_ASM_COMPILE_FLAGS}")
        target_compile_options(hello_asm PRIVATE ${HELLO_ASM_COMPILE_FLAGS_LIST})
    endif()

    if(HELLO_ASM_LINK_FLAGS)
        separate_arguments(HELLO_ASM_LINK_FLAGS_LIST NATIVE_COMMAND "${HELLO_ASM_LINK_FLAGS}")
        target_link_options(hello_asm PRIVATE ${HELLO_ASM_LINK_FLAGS_LIST})
    endif()
else()
    message(WARNING "No assembly source found for TARGET_ARCH=${TARGET_ARCH}; hello_asm will not be built")
endif()

# ------------------------------------------------------------
# Go
# ------------------------------------------------------------
find_program(GO_EXECUTABLE go)
if(GO_EXECUTABLE)
    set(GO_BUILD_ENV
        "GOOS=$ENV{GOOS}"
        "GOARCH=$ENV{GOARCH}"
    )

    if(DEFINED ENV{GOARM} AND NOT "$ENV{GOARM}" STREQUAL "")
        list(APPEND GO_BUILD_ENV "GOARM=$ENV{GOARM}")
    endif()

    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/hello_go
        COMMAND ${CMAKE_COMMAND} -E env ${GO_BUILD_ENV}
                ${GO_EXECUTABLE} build
                -o ${CMAKE_BINARY_DIR}/hello_go
                ${CMAKE_CURRENT_SOURCE_DIR}/hello.go
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hello.go
        COMMENT "Building Go hello world for ${TARGET_ARCH}"
        VERBATIM
    )
    add_custom_target(build_hello_go ALL DEPENDS ${CMAKE_BINARY_DIR}/hello_go)
else()
    message(WARNING "Go not found; hello_go will not be built")
endif()

# ------------------------------------------------------------
# Rust
# ------------------------------------------------------------
find_program(RUSTC_EXECUTABLE rustc)
if(RUSTC_EXECUTABLE)
    set(RUST_CMD ${RUSTC_EXECUTABLE})

    if(DEFINED ENV{RUST_TARGET} AND NOT "$ENV{RUST_TARGET}" STREQUAL "")
        list(APPEND RUST_CMD --target "$ENV{RUST_TARGET}")
    endif()

    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/hello_rust
        COMMAND ${RUST_CMD}
                ${CMAKE_CURRENT_SOURCE_DIR}/hello.rs
                -o ${CMAKE_BINARY_DIR}/hello_rust
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hello.rs
        COMMENT "Building Rust hello world for ${TARGET_ARCH}"
        VERBATIM
    )
    add_custom_target(build_hello_rust ALL DEPENDS ${CMAKE_BINARY_DIR}/hello_rust)
else()
    message(WARNING "rustc not found; hello_rust will not be built")
endif()

# ------------------------------------------------------------
# Dart
# ------------------------------------------------------------
find_program(DART_EXECUTABLE dart)
if(DART_EXECUTABLE)
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/hello_dart
        COMMAND ${DART_EXECUTABLE} compile exe
                ${CMAKE_CURRENT_SOURCE_DIR}/hello.dart
                -o ${CMAKE_BINARY_DIR}/hello_dart
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hello.dart
        COMMENT "Building Dart hello world for ${TARGET_ARCH}"
        VERBATIM
    )
    add_custom_target(build_hello_dart ALL DEPENDS ${CMAKE_BINARY_DIR}/hello_dart)
else()
    message(WARNING "Dart SDK not found; hello_dart will not be built")
endif()
