cmake_minimum_required(VERSION 3.9)

project(YOUSHALLNOTPASS)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)
set(SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)

include(FetchContent)

# link libpcap to project.
find_library(libpcap_location NAMES libpcap.so)
if(libpcap_location)
    message(STATUS "libpcap location is: ${libpcap_location}")
    add_library(libpcap SHARED IMPORTED)
    set_target_properties(libpcap PROPERTIES IMPORTED_LOCATION ${libpcap_location})
else()
    message(FATAL_ERROR "Cannot find lipcap download from https://www.tcpdump.org/")
endif()

set(SRC
    src/lpcap.cc
    src/parser.cc)

add_library(PParser STATIC ${SRC})
target_compile_features(PParser PRIVATE cxx_std_11)
target_link_libraries(PParser PRIVATE libpcap)

# Build main target.
add_executable(main main.cc)
target_link_libraries(main PRIVATE libpcap)
target_link_libraries(main PUBLIC PParser)
target_compile_features(main PUBLIC cxx_std_11)
