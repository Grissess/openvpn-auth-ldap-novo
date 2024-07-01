cmake_minimum_required(VERSION 3.4...3.22)
project(openldap-auth-ldap-novo
	VERSION 0.1
	DESCRIPTION "An OpenVPN plugin for using LDAP BIND as an authentication method"
	LANGUAGES C
)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENLDAP REQUIRED ldap)

include(CheckCSourceCompiles)
check_c_source_compiles("
#include <openvpn/openvpn-plugin.h>
int main() { return 0; }
" HAVE_OPENVPN)
if(NOT HAVE_OPENVPN)
	message(FATAL_ERROR "No <openvpn/openvpn-plugin.h> could be found in the default path or INCLUDE_DIRECTORIES. Is OpenVPN installed?")
endif()

add_subdirectory(src)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
	${CMAKE_CURRENT_BINARY_DIR}/openldap-auth-ldap-novo-config-version.cmake
	COMPATIBILITY SameMajorVersion
)
