cmake_minimum_required(VERSION 3.5)
project(Pcap_parser)


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)

include_directories(${INCLUDE_DIR})

set(SOURCES
        ${SRC_DIR}/main.cpp
        ${SRC_DIR}/pcap_reader.cpp
        ${SRC_DIR}/ethernet_parser.cpp
        ${SRC_DIR}/ip_packet_manager.cpp
        ${SRC_DIR}/ethernet_parser.cpp
)

set(HEADERS
        ${INCLUDE_DIR}/structs/pcap_structs.h
        ${INCLUDE_DIR}/structs/ethernet_structs.h
        ${INCLUDE_DIR}/pcap_reader.h
        ${INCLUDE_DIR}/ethernet_parser.h
        ${INCLUDE_DIR}/ip_packet_manager.h
        ${INCLUDE_DIR}/CArrayWrapper.h
)

add_executable(Pcap_parser ${SOURCES} ${HEADERS})

# Настройки компилятора
if (MSVC)
    target_compile_options(Pcap_parser PRIVATE /W3)
    target_compile_definitions(Pcap_parser PRIVATE _CRT_SECURE_NO_WARNINGS)
else ()
    target_compile_options(Pcap_parser PRIVATE -Wall -Wextra -pedantic)
endif ()

add_custom_command(TARGET Pcap_parser POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/result
        COMMENT "Создание папки result для выходных файлов"
)


# === ИНФОРМАЦИЯ О СБОРКЕ ===
message(STATUS "")
message(STATUS "=== Конфигурация сборки ===")
message(STATUS "Компилятор: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Стандарт C++: ${CMAKE_CXX_STANDARD}")
message(STATUS "Тип сборки: ${CMAKE_BUILD_TYPE}")
message(STATUS "==========================")