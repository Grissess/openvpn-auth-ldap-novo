add_library(openldap-auth-ldap-novo-plugin SHARED
	plugin.c
)
target_link_libraries(openldap-auth-ldap-novo-plugin ${OPENLDAP_LIBRARIES})
target_include_directories(openldap-auth-ldap-novo-plugin PUBLIC ${OPENLDAP_INCLUDE_DIRS})
target_compile_options(openldap-auth-ldap-novo-plugin PUBLIC ${OPENLDAP_CFLAGS_OTHER})
