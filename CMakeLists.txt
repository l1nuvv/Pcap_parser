cmake_minimum_required(VERSION 3.5)
project(Pcap_parser)

# Настройка стандарта C++
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)

include_directories(${INCLUDE_DIR})

set(SOURCES
        ${SRC_DIR}/main.cpp
        ${SRC_DIR}/pcap_reader.cpp
)

set(HEADERS
        ${INCLUDE_DIR}/pcap_structs.h
        ${INCLUDE_DIR}/pcap_reader.h
        ${INCLUDE_DIR}/ethernet_structs.h
)

add_executable(Pcap_parser ${SOURCES} ${HEADERS})

# Настройки компилятора
if(MSVC)
    target_compile_options(Pcap_parser PRIVATE /W3)
    target_compile_definitions(Pcap_parser PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(Pcap_parser PRIVATE -Wall -Wextra -pedantic)
endif()

add_custom_command(TARGET Pcap_parser POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/result
        COMMENT "Создание папки result для выходных файлов"
)

if(BUILD_TESTS)
    # Попытка найти локально установленный GTest
    find_package(GTest QUIET)

    if(NOT GTest_FOUND)
        message(STATUS "GTest не найден локально, загружаем из интернета...")

        include(FetchContent)

        FetchContent_Declare(
                googletest
                GIT_REPOSITORY https://github.com/google/googletest.git
                GIT_TAG release-1.12.1
        )

        # Настройки для Windows
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

        FetchContent_MakeAvailable(googletest)

        if(TARGET gtest_main)
            set(GTEST_AVAILABLE TRUE)
        else()
            message(WARNING "Не удалось загрузить Google Test. Тесты отключены.")
            set(GTEST_AVAILABLE FALSE)
        endif()
    else()
        message(STATUS "Используем локально установленный GTest")
        set(GTEST_AVAILABLE TRUE)
    endif()

    if(GTEST_AVAILABLE)
        enable_testing()

        add_executable(pcap_tests
                tests/test_pcap_reader.cpp
                src/pcap_reader.cpp  # Только один раз!
        )

        # Подключение библиотек
        if(GTest_FOUND)
            target_link_libraries(pcap_tests GTest::gtest_main)
        else()
            target_link_libraries(pcap_tests gtest_main)
        endif()

        # Заголовочные файлы для тестов
        target_include_directories(pcap_tests PRIVATE ${INCLUDE_DIR})

        # Регистрация тестов
        include(GoogleTest)
        gtest_discover_tests(pcap_tests)

        message(STATUS "Тесты включены. Запуск: make test или ctest")
    endif()
else()
    message(STATUS "Тесты отключены. Для включения: cmake -DBUILD_TESTS=ON ..")
endif()

# === ИНФОРМАЦИЯ О СБОРКЕ ===
message(STATUS "")
message(STATUS "=== Конфигурация сборки ===")
message(STATUS "Компилятор: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Стандарт C++: ${CMAKE_CXX_STANDARD}")
message(STATUS "Тип сборки: ${CMAKE_BUILD_TYPE}")
message(STATUS "Тесты: ${BUILD_TESTS}")
message(STATUS "==========================")