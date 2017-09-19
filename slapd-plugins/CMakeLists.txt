add_library(liblpws_slapd SHARED lpws.c)
set_target_properties(liblpws_slapd PROPERTIES OUTPUT_NAME lpws)
install(TARGETS liblpws_slapd LIBRARY DESTINATION lib/openldap)
