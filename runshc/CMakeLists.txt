cmake_minimum_required (VERSION 3.0)

project ( runshc )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	util.cpp
)

set (hdrs
	util.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
