cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME AsioTls)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(${PROJECT_NAME})

add_subdirectory(client)
add_subdirectory(server)
