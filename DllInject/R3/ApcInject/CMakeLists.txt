# CMakeList.txt: Apc-Inject 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

project ("ApcInject")

# 将源代码添加到此项目的可执行文件。
add_executable (ApcInject "ApcInject.cpp" "ApcInject.h")

if(MSVC)	
	add_definitions(-DUNICODE -D_UNICODE -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
endif()