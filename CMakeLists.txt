cmake_minimum_required (VERSION 3.0.2)

project(WinDbgFastObj)

add_library( 
	${PROJECT_NAME}
	SHARED
	src/WinDbgFastObj.cpp
	src/wdbgexts.h

	third_party/Detours/src/detours.cpp
	third_party/Detours/src/disasm.cpp
	third_party/Detours/src/modules.cpp
	)

set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "/W4 /WX /MT /std:c++17")
target_include_directories(${PROJECT_NAME} PRIVATE "./third_party/Detours/src")