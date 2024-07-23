cmake_minimum_required(VERSION 3.12)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_STANDARD 17)

project(co_http LANGUAGES CXX)

add_compile_options(-Wall -Wextra -Werror=return-type)

find_package(Threads REQUIRED)
find_package(fmt REQUIRED)

file(GLOB sources CONFIGURE_DEPENDS *.cpp)
foreach (source IN ITEMS ${sources})
    get_filename_component(name "${source}" NAME_WLE)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE Threads::Threads fmt::fmt)
    target_include_directories(${name} PRIVATE include)
endforeach()
