cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0-a4)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()

set(PICO_BOARD pico2_w CACHE STRING "Board type")

include(pico_sdk_import.cmake)

project(blink_any C CXX ASM)

pico_sdk_init()

add_executable(blink_any
    blink_any.c
    mfrc522.c
    net.c
)

# lwipopts.h and (optional, git-ignored) wifi_config.h live next to the sources
target_include_directories(blink_any PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(blink_any
    pico_stdlib
    pico_rand
    hardware_spi
    pico_cyw43_arch_lwip_threadsafe_background
)

# Diagnostic build: cmake -DRFID_DIAG=ON ... prints register changes after boot
option(RFID_DIAG "Build the reader with the register-watch diagnostic enabled" OFF)
if(RFID_DIAG)
    target_compile_definitions(blink_any PRIVATE RFID_DIAG=1)
endif()

pico_enable_stdio_usb(blink_any 1)
pico_enable_stdio_uart(blink_any 0)

pico_add_extra_outputs(blink_any)