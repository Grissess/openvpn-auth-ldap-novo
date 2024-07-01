#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openvpn/openvpn-plugin.h>
/* We're still using simple_bind for now */
#define LDAP_DEPRECATED 1
#include <ldap.h>

static char *MODULE = "openvpn-auth-ldap-novo";

struct plugin_state {
	struct openvpn_plugin_callbacks *callbacks;
	char *ldap_uri;
	char *bind_dn;
	char *bind_pw;
	char *base;
	int scope;
	char *filter;
};

static void cleanup_context(struct plugin_state *context) {
#define FREE(x) if(x) free(x);
	FREE(context->ldap_uri);
	FREE(context->bind_dn);
	FREE(context->bind_pw);
	FREE(context->base);
	FREE(context->filter);
#undef FREE
}

/* Provenance: returns a newly malloc'd (strdup'd) string */
static char *lookup_var(const char **env, const char *name) {
	size_t sz;
	const char **here = env;

	if(!env || !name) return NULL;
	sz = strlen(name);
	while(*here) {
		if(strncmp(*here, name, sz)) {
			here++;
			continue;
		}
		if(strlen(*here) < sz + 1) { /* Need room for that = */
			here++;
			continue;
		}
		if((*here)[sz] != '=') {
			here++;
			continue;
		}
		return strdup((*here) + sz + 1);
	}
	return NULL;
}

/* We're using the base64 functions */
OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1() { return 5; }
#define CHECK_VERSION(ver) do { if((ver) < openvpn_plugin_min_version_required_v1()) { \
	fprintf(stderr, "%s: Incompatible versions (required %d, actual %d)\n", \
			MODULE, \
			openvpn_plugin_min_version_required_v1(), \
			v3structver \
			); \
	return OPENVPN_PLUGIN_FUNC_ERROR; \
}} while(0)

OPENVPN_EXPORT int openvpn_plugin_open_v3(const int v3structver,
		struct openvpn_plugin_args_open_in const *args,
		struct openvpn_plugin_args_open_return *ret) {
	struct plugin_state *context = NULL;
	int err;
	char *scope;

	CHECK_VERSION(v3structver);

	context = (struct plugin_state *)calloc(1, sizeof(struct plugin_state));
	if(!context) {
		args->callbacks->plugin_log(PLOG_ERR, MODULE, "Could not allocate context");
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	context->callbacks = args->callbacks;
#define FAIL_IF(cond, msg...) do { if(cond) { \
	context->callbacks->plugin_log(PLOG_ERR, MODULE, msg); \
	if(context) { \
		cleanup_context(context); \
		free(context); \
	} \
	return OPENVPN_PLUGIN_FUNC_ERROR; \
}} while(0)

	FAIL_IF(!(context->ldap_uri = lookup_var(args->argv, "ldap-uri")), "No ldap-uri specified");

	if(!(context->base = lookup_var(args->argv, "base"))) {
		context->base = "";
	}

	if(!(scope = lookup_var(args->argv, "scope"))) {
		scope = strdup("subtree");  /* we must be able to free() this */
	}

	if(!strcmp(scope, "base")) {
		context->scope = LDAP_SCOPE_BASE;
	} else if(!strcmp(scope, "onelevel")) {
		context->scope = LDAP_SCOPE_ONELEVEL;
	} else if(!strcmp(scope, "subtree")) {
		context->scope = LDAP_SCOPE_SUBTREE;
	} else if(!strcmp(scope, "children")) {
		context->scope = LDAP_SCOPE_CHILDREN;
	} else {
		free(scope);
		FAIL_IF(1, "Invalid scope '%s': must be one of base, onelevel, subtree, or children", scope);
	}

	free(scope);

	if(!(context->filter = lookup_var(args->argv, "filter"))) {
		context->filter = strdup("(cn=%s)");
	}

	{
		char *ch;
		int count = 0;
		for(ch = context->filter; ch && *ch; ch++) {
			if(*ch == '%') {
				FAIL_IF(++count > 1, "Too many %%s in filter; at most one %%s is allowed");
				/* Safety: at worst we read the NUL terminator here due to the loop cond */
				FAIL_IF(ch[1] != 's', "Filter may only use %%s");
			}
		}
	}

	context->bind_dn = lookup_var(args->argv, "bind-dn");
	if(context->bind_dn) {
		if(!(context->bind_pw = lookup_var(args->argv, "bind-pw"))) {
			char *path = lookup_var(args->argv, "bind-pw-file");
			FILE *f;
			long size;
			size_t read;

			FAIL_IF(!path,
					"bind-pw or bind-pw-file is required when bind-dn is given"
			);
			FAIL_IF(!(f = fopen(path, "r")),
					"bind-pw-file '%s' could not be opened: (%d)%s",
					path, errno, strerror(errno)
			);
			/* Need to start doing some cleanup at this point */
#define CLOSE_FILE_IF(cond, msg...) do { if(cond) { \
	fclose(f); \
	FAIL_IF(1, msg); \
}} while(0)
			CLOSE_FILE_IF(fseek(f, 0, SEEK_END), "failed to seek on '%s': (%d)%s",
					path, errno, strerror(errno)
			);
			CLOSE_FILE_IF((size = ftell(f)) < 0, "failed to get size of '%s': (%d)%s",
					path, errno, strerror(errno)
			);
			rewind(f);
			context->bind_pw = malloc(size);  /* Security: assured >= 0 here */
			CLOSE_FILE_IF(!context->bind_pw, "Could not allocate memory for bind pw");
			if((read = fread(context->bind_pw, 1, size, f)) < size) {
				context->callbacks->plugin_log(PLOG_WARN, MODULE,
						"possible short read on pw file '%s' (read %zu), there may be trouble ahead",
						path, read
				);
			}
			if(fclose(f)) {
				context->callbacks->plugin_log(PLOG_WARN, MODULE,
						"failed to close '%s', proceeding anyway",
						path
				);
			}
		}
	}

	ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
	ret->handle = context;
	return OPENVPN_PLUGIN_FUNC_SUCCESS;
#undef FAIL_IF
}

OPENVPN_EXPORT int openvpn_plugin_func_v3(const int v3structver,
		struct openvpn_plugin_args_func_in const *args,
		struct openvpn_plugin_args_func_return *ret) {
	struct plugin_state *context = (struct plugin_state *)args->handle;
	LDAP *ldap, *ldap_user;
	LDAPMessage *search = NULL, *entry;
	char *filter, *username, *password, *dn, buffer;
	int err;
	int res = OPENVPN_PLUGIN_FUNC_ERROR;

	CHECK_VERSION(v3structver);

	if(!context) {
		fprintf(stderr, "%s: Bad context, aborting\n", MODULE);
		goto out;
	}

	if((err = ldap_initialize(&ldap, context->ldap_uri)) != LDAP_SUCCESS) {
		context->callbacks->plugin_log(PLOG_WARN, MODULE,
				"Failed to initialize connection to LDAP server (uri %s): (%d)%s",
				context->ldap_uri, err, ldap_err2string(err)
		);
		goto out;
	}

	if(context->bind_dn) {
		if((err = ldap_simple_bind_s(ldap, context->bind_dn, context->bind_pw)) != LDAP_SUCCESS) {
			context->callbacks->plugin_log(PLOG_WARN, MODULE,
					"Failed to bind to LDAP server (uri %s) as %s: (%d)%s",
					context->ldap_uri, context->bind_dn, err, ldap_err2string(err)
			);
			goto out_free_ldap;
		}
	}

	username = lookup_var(args->envp, "username");
	password = lookup_var(args->envp, "password");
	if(!username || !password) {
		context->callbacks->plugin_log(PLOG_WARN, MODULE, "No username or password provided");
		goto out_free_creds;
	}

	/* Safety: while a user could spoof this, they'd need to know the password anyway */
	/* NB: this doesn't work with a CRV1 "dynamic" CR, the password doesn't seem to be encoded */
	if(!strncmp(password, "SCRV1:", 6)) {
		char *start, *end, *encoded;
		size_t buffer_size;
		int actual_size;
		context->callbacks->plugin_log(PLOG_DEBUG, MODULE, "Password is an SCRV1");
		start = password + 5;  /* This one's at a fixed length */
		end = strchr(start + 1, ':');  /* Safety: at worst we index the NUL terminator */
		if(!end) {
			context->callbacks->plugin_log(PLOG_WARN, MODULE, "Invalid SCRV1 password: no second : found");
			goto out_free_ldap;
		}
		/* Safety: this won't overflow but could fail if the allocation is huge */
		encoded = malloc(end - start);  /* start -> ':', so this includes the +1 for NUL */
		if(!encoded) {
			context->callbacks->plugin_log(PLOG_WARN, MODULE, "Out of memory copying SCRV1 password");
			goto out_free_ldap;
		}
		/* Safety: end > start because the search starts at start+1 */
		memcpy(encoded, start + 1, (end - start) - 1);
		encoded[(end - start) - 1] = 0;
		/* Safety: overflow check here is tricky, we're admittedly assuming the password length is sane */
		buffer_size = ((size_t)(end - start) * 3 + 3) / 4 + 1;
		password = malloc(buffer_size);
		if(!password) {
			free(encoded);
			context->callbacks->plugin_log(PLOG_WARN, MODULE, "Out of memory parsing SCRV1 password");
			goto out_free_creds;
		}
		if((actual_size = context->callbacks->plugin_base64_decode(encoded, password, buffer_size)) < 0) {
			free(encoded);
			context->callbacks->plugin_log(PLOG_WARN, MODULE, "Failed to decode SCRV1 password");
			goto out_free_creds;
		}
		if(actual_size >= buffer_size) {
			free(encoded);
			context->callbacks->plugin_log(PLOG_WARN, MODULE, "SCRV1 password too big");
			goto out_free_creds;
		}
		password[actual_size] = 0;
		free(encoded);
	} else {
		context->callbacks->plugin_log(PLOG_DEBUG, MODULE, "Password is not an SCRV1");
		password = strdup(password);  /* To ensure it can be free()d later */
	}

	/* Safety: context->filter is trusted and validated on plugin open */
	if((err = snprintf(&buffer, 1, context->filter, username)) < 0) {
		context->callbacks->plugin_log(PLOG_WARN, MODULE,
				"snprintf returned error code--is your libc old or non-compliant?"
		);
		goto out_free_creds;
	}
	filter = malloc(err + 1);
	snprintf(filter, err + 1, context->filter, username);

	if((err = ldap_search_ext_s(ldap,
			context->base, context->scope, filter,
			NULL, 0, NULL, NULL, NULL, 1, &search
	)) != LDAP_SUCCESS) {
		context->callbacks->plugin_log(PLOG_NOTE, MODULE, "Unable to search '%s' in '%s': (%d)%s",
				filter, context->ldap_uri, err, ldap_err2string(err)
		);
		goto out_free_search;
	}

	if(!(entry = ldap_first_entry(ldap, search))) {
		context->callbacks->plugin_log(PLOG_NOTE, MODULE, "No results for '%s' in '%s'",
				filter, context->ldap_uri
		);
		goto out_free_search;
	}
	dn = ldap_get_dn(ldap, entry);

	/* Use a second connection to test the bind; OpenLDAP treats unbind() as free() */
	if((err = ldap_initialize(&ldap_user, context->ldap_uri)) != LDAP_SUCCESS) {
		context->callbacks->plugin_log(PLOG_WARN, MODULE,
				"Failed to connect to LDAP server (uri '%s') to test user credentials: (%d)%s",
				context->ldap_uri, err, ldap_err2string(err)
		);
		goto out_free_dn;
	}

	if((err = ldap_simple_bind_s(ldap_user, dn, password)) != LDAP_SUCCESS) {
		context->callbacks->plugin_log(PLOG_NOTE, MODULE,
				"Failed to bind as '%s' to '%s': (%d)%s",
				dn, context->ldap_uri, err, ldap_err2string(err)
		);
		goto out_free_ldap_user;
	}

	/* If we're here, success: the password was valid for the DN. */
	res = OPENVPN_PLUGIN_FUNC_SUCCESS;

out_free_ldap_user:
	ldap_unbind_s(ldap_user);
out_free_dn:
	ldap_memfree(dn);
out_free_search:
	ldap_msgfree(search);
out_free_filter:
	free(filter);
out_free_creds:
	if(username) free(username);
	if(password) free(password);
out_free_ldap:
	ldap_unbind_ext_s(ldap, NULL, NULL);
out:
	return res;
}

/*
	FAIL_IF((err = ldap_initialize(&context->ldap, context->ldap_uri)) != LDAP_SUCCESS,
			"Failed to initialize connection to LDAP server (uri %s): (%d)%s",
			context->ldap_uri, err, ldap_err2string(err)
	);
	FAIL_IF((err = ldap_simple_bind_s(context->ldap, context->bind_dn, context->bind_pw)) != LDAP_SUCCESS,
			"Failed to initially bind to LDAP server (uri %s) as %s: (%d)%s",
			context->ldap_uri, context->bind_dn, err, ldap_err2string(err)
	);
*/
