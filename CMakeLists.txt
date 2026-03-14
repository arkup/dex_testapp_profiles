cmake_minimum_required(VERSION 3.22.1)
project("native_protector")

add_library(native_protector SHARED
    app/src/main/cpp/native_protector.cpp)

find_library(log-lib log)
target_link_libraries(native_protector ${log-lib})

target_link_options(native_protector PRIVATE "-Wl,-z,max-page-size=16384")
