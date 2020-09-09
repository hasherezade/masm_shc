cmake_minimum_required (VERSION 2.8)

project ( masm_shc )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	main.cpp
	string_util.cpp
)

set (hdrs
	string_util.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

