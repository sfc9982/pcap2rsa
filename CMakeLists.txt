cmake_minimum_required(VERSION 3.11)
# cmake_policy(SET CMP0144 NEW)
cmake_policy(SET CMP0074 NEW)

project("pcap2rsa")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(TARGET_NAME pcap2rsa)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)

set(Boost_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/boost_1_88_0/output)
set(PCAP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/npcap-sdk-1.15)
set(Packet_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/npcap-sdk-1.15)
set(PcapPlusPlus_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/pcapplusplus-24.09-windows-mingw64-x86_64-gcc-14.1.0)

# https://cmake.org/cmake/help/latest/policy/CMP0167.html
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

find_package(Boost REQUIRED)
find_package(PcapPlusPlus CONFIG REQUIRED)

message(STATUS "Using Pcap++ ${PcapPlusPlus_VERSION}")
message(STATUS "Include dir: ${PcapPlusPlus_INCLUDE_DIR}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/args)

# include_directories(<HEADER_PATH>)
# add_link_options(<LINKER_FLAGS>)
# add_compile_options(<COMPILER_FLAGS>)

aux_source_directory(./src SOURCE_FILES)
add_executable(${TARGET_NAME} ${SOURCE_FILES})
# target_compile_options(${TARGET_NAME} PRIVATE -stdlib=libstdc++ --target=x86_64-pc-windows-gnu -isystem "C:\\Users\\sfc9982\\Desktop\\EDX\\toolsets\\llvm-mingw-20240308-msvcrt-x86_64\\include\\c++\\v1")

target_link_options(${TARGET_NAME} PRIVATE -static)
target_link_libraries(${TARGET_NAME} PRIVATE PcapPlusPlus::Packet++ PcapPlusPlus::Pcap++ PcapPlusPlus::Common++ Boost::boost)

# target_precompile_headers(${TARGET_NAME} PRIVATE pch_header.h)

# target_link_libraries(${TARGET_NAME}
#    <LIB_NAME>
# )

# set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/output/${CMAKE_C_COMPILER_ID}-${CMAKE_C_COMPILER_ARCHITECTURE_ID}-${CMAKE_BUILD_TYPE})

#install(TARGETS ${TARGET_NAME}
#        RUNTIME_DEPENDENCIES
#        PRE_EXCLUDE_REGEXES "system32/|((api-ms-).*\\.dll)|/usr/|/lib/|/lib64/"
#        POST_EXCLUDE_REGEXES "system32/|((api-ms-).*\\.dll)|/usr/|/lib/|/lib64/"
#        RUNTIME DESTINATION bin
#        LIBRARY DESTINATION lib
#        ARCHIVE DESTINATION lib)

# install(FILES ${SOURCE_FILES}
#    DESTINATION src)