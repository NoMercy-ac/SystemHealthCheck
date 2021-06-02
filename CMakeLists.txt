cmake_minimum_required(VERSION 3.2)
project(SystemHealthCheck CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ../Bin/)

add_definitions(-DFMT_HEADER_ONLY) # fmt
add_definitions(-DSPDLOG_NO_TLS) # spdlog

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(ARCH_STR "64")
	add_definitions(-DBUILD_ARCH=64)
else() 
	set(ARCH_STR "86")
	add_definitions(-DBUILD_ARCH=86)
endif()

include_directories(${PROJECT_SOURCE_DIR}/extern/include)
link_directories(${PROJECT_SOURCE_DIR}/extern/lib_x${ARCH_STR})

if(MSVC)
	set(LIB_RT_SUFFIX "mt")
	set(LIB_RT_OPTION "/MT")

	foreach(flag_var  CMAKE_C_FLAGS  CMAKE_CXX_FLAGS)
		 foreach(config_name  ""  DEBUG  RELEASE  MINSIZEREL  RELWITHDEBINFO)
			set(var_name "${flag_var}")

			if(NOT "${config_name}" STREQUAL "")
				set(var_name "${var_name}_${config_name}")
			endif()
			
			string(REPLACE "/MD" "${LIB_RT_OPTION}" ${var_name} "${${var_name}}")
			set(${var_name} "${${var_name}}" CACHE STRING "" FORCE)
		endforeach()
	endforeach()

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${MT_BUILD}")
endif()

file(GLOB _HEADER_FILES
	"${PROJECT_SOURCE_DIR}/include/*.hpp"
)
file(GLOB _SOURCE_FILES
	"${PROJECT_SOURCE_DIR}/src/*.cpp"
)

add_executable(${PROJECT_NAME}
    ${_HEADER_FILES}
    ${_SOURCE_FILES}
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CMAKE_CXX_EXTENSIONS OFF)

target_precompile_headers(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include/pch.hpp)

target_link_libraries(${PROJECT_NAME} amsi shlwapi srclient wbemuuid wininet wintrust)

SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator'\"")
