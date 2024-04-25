cmake_minimum_required(VERSION 3.22.1)

project("cdbcapp")

add_library(${CMAKE_PROJECT_NAME} SHARED
        native-lib.cpp)
add_library(libgnark SHARED IMPORTED)
set_property(TARGET libgnark PROPERTY IMPORTED_NO_SONAME 1)
set_target_properties(libgnark PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${CMAKE_ANDROID_ARCH_ABI}/libgnark.so)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${CMAKE_ANDROID_ARCH_ABI}/)
target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        libgnark)