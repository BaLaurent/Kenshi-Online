# Cross-compile the KenshiMP Windows targets (KenshiMP.Core, Injector, Scanner, …)
# on Linux with clang-cl + lld-link, against the MSVC CRT + Windows SDK fetched by xwin.
# Produces MSVC-ABI x64 PE binaries — no Windows host, no Wine, no MinGW required.
# See docs/LINUX-CLIENT-BUILD.md for the full recipe.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

# xwin ships only the RELEASE CRT/SDK import libs (no debug msvcrtd.lib). Force the
# release dynamic runtime (/MD) everywhere and build Release — this also matches the
# game's own Release DLLs (the _ITERATOR_DEBUG_LEVEL=0 ABI note in the root CMakeLists).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
set(CMAKE_TRY_COMPILE_CONFIGURATION "Release")

# Location of the xwin splat output. Override with -DXWIN_DIR=... if not in ~/.xwin.
if(NOT DEFINED XWIN_DIR)
    set(XWIN_DIR "$ENV{HOME}/.xwin")
endif()

set(CMAKE_C_COMPILER   clang-cl)
set(CMAKE_CXX_COMPILER clang-cl)
set(CMAKE_C_COMPILER_TARGET   x86_64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-windows-msvc)
set(CMAKE_LINKER lld-link)
set(CMAKE_AR llvm-lib)
set(CMAKE_MT llvm-mt)
set(CMAKE_RC_COMPILER llvm-rc)

# System includes (suppress SDK-header warnings). Four families: MSVC STL, UCRT,
# Windows-SDK user-mode, and shared.
set(_kmp_incs "-imsvc ${XWIN_DIR}/crt/include -imsvc ${XWIN_DIR}/sdk/include/ucrt -imsvc ${XWIN_DIR}/sdk/include/um -imsvc ${XWIN_DIR}/sdk/include/shared")
set(CMAKE_C_FLAGS_INIT   "${_kmp_incs} -fuse-ld=lld")
set(CMAKE_CXX_FLAGS_INIT "${_kmp_incs} -fuse-ld=lld")

# Import-lib search paths for the linker.
set(_kmp_libs "/libpath:${XWIN_DIR}/crt/lib/x86_64 /libpath:${XWIN_DIR}/sdk/lib/um/x86_64 /libpath:${XWIN_DIR}/sdk/lib/ucrt/x86_64")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_kmp_libs}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_kmp_libs}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_kmp_libs}")

set(CMAKE_FIND_ROOT_PATH "${XWIN_DIR}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
