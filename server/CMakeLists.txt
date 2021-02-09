set(SERVER_EXEC_NAME server)

add_executable(${SERVER_EXEC_NAME}
    connection.cc
    server.cc
    main.cc
)

target_link_libraries(${SERVER_EXEC_NAME}
    crypto
    pthread
    ssl
)
