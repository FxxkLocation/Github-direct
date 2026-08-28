cmake_minimum_required(VERSION 3.22.1)
project(ghdnet LANGUAGES CXX)

add_library(ghdnet SHARED original_destination.cpp)
target_compile_features(ghdnet PRIVATE cxx_std_17)
target_compile_options(ghdnet PRIVATE -Wall -Wextra -Werror)
target_link_options(ghdnet PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)
