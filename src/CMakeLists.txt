add_library(openvpn-auth-ldap-novo-plugin SHARED
	plugin.c
)
target_link_libraries(openvpn-auth-ldap-novo-plugin ${OPENLDAP_LIBRARIES})
target_include_directories(openvpn-auth-ldap-novo-plugin PUBLIC ${OPENLDAP_INCLUDE_DIRS})
target_compile_options(openvpn-auth-ldap-novo-plugin PUBLIC ${OPENLDAP_CFLAGS_OTHER})
install(TARGETS openvpn-auth-ldap-novo-plugin)
