cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME AsioTls)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(${PROJECT_NAME})

if (OSX_BUILD)
    include_directories(/usr/local/include/)
    include_directories(/usr/local/Cellar/openssl\@1.1/1.1.1i/include/)
    link_directories(/usr/local/Cellar/openssl\@1.1/1.1.1i/lib/)
endif()

add_subdirectory(client)
add_subdirectory(server)
