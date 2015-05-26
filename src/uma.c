#include "mod_auth_ox.h"
#include "oxd_main.h"

/**
* Returns true if the current request in the connection has an
* "X-Forwarded-Proto: https" header from a trusted BIG IP proxy.
* This emulates the ssl_is_https(conn_rec *) function in mod_ssl
* and is used to populate the %{HTTPS} variable in mod_rewrite,
* for example.
*/
static int ssl_is_https(conn_rec *c) {
	const char *https;
	https = apr_table_get(c->notes, BIGIP_HTTPS_NOTE);
	return (https) && (0 == strcmp(https, BIGIP_HTTPS_ON));
}

// Get the full URI of the request_rec's request location 
// clean_params specifies whether or not all openid.* and modoic.* params should be cleared
static void full_uri(request_rec *r, std::string& result, ox_cfg *cfg, char *return_uri=NULL, bool clean_params=false) {
	std::string hostname(r->hostname);
	std::string uri = (return_uri)?std::string(return_uri):std::string(r->uri);
	apr_port_t i_port = ap_get_server_port(r);
	// Fetch the APR function for determining if we are looking at an https URL
	std::string prefix = ssl_is_https(r->connection) ? "https://" : "http://";
	char *port = apr_psprintf(r->pool, "%lu", (unsigned long) i_port);
	std::string s_port = (i_port == 80 || i_port == 443) ? "" : ":" + std::string(port);

	std::string args;
	if(clean_params) {
		opkele::params_t params;
		if(r->args != NULL) params = modox::parse_query_string(std::string(r->args));
		modox::remove_openid_vars(params);
		args = params.append_query("", "");
	} else {
		args = (r->args == NULL) ? "" : "?" + std::string(r->args);
	}

	result = prefix + hostname + s_port + uri + args;
}

/*
* check oxd discovery infos in memcached.
* true : unchanged, false : changed
*/
static bool uma_check_discovery_infos(ox_cfg *cfg)
{
	bool ret = true;

	char *oxdhost = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.oxdhost");
	char *discovery = Get_Ox_Storage(cfg->OpenIDClientName, "connect.discovery");
	char *creditpath = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.creditpath");
	char *uma_discovery = Get_Ox_Storage(cfg->OpenIDClientName, "uma.discovery");
	char *uma_resource = Get_Ox_Storage(cfg->OpenIDClientName, "uma.resource");
	char *uma_rshost = Get_Ox_Storage(cfg->OpenIDClientName, "uma.rshost");

	if (!oxdhost || !discovery || !redirect || !clientname || !uma_discovery || !uma_resource || !uma_rshost || (!creditpath && cfg->ClientCredsPath))
	{
		Set_Ox_Storage(cfg->OpenIDClientName, "oxd.oxdhost", cfg->OxdHostAddr, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "connect.discovery", cfg->OpenIDProvider, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "connect.redirect", cfg->OpenIDClientRedirectURIs, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "oxd.clientname", cfg->OpenIDClientName, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "oxd.creditpath", cfg->ClientCredsPath, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "uma.discovery", cfg->UmaAuthorizationServer, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "uma.resource", cfg->UmaResourceName, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "uma.rshost", cfg->uma_rs_host, 0);

		ret = false; 
		goto EXIT_check_discovery_infos;
	}

	if (strcmp(oxdhost, cfg->OxdHostAddr) ||
		strcmp(discovery, cfg->OpenIDProvider) ||
		strcmp(redirect, cfg->OpenIDClientRedirectURIs) ||
		strcmp(clientname, cfg->OpenIDClientName) ||
		strcmp(uma_discovery, cfg->UmaAuthorizationServer) ||
		strcmp(uma_resource, cfg->UmaResourceName) ||
		strcmp(uma_rshost, cfg->uma_rs_host) || 
		(cfg->ClientCredsPath && strcmp(creditpath, cfg->ClientCredsPath)))
	{
		Set_Ox_Storage(cfg->OpenIDClientName, "oxd.oxdhost", cfg->OxdHostAddr, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "connect.discovery", cfg->OpenIDProvider, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "connect.redirect", cfg->OpenIDClientRedirectURIs, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "oxd.clientname", cfg->OpenIDClientName, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "oxd.creditpath", cfg->ClientCredsPath, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "uma.discovery", cfg->UmaAuthorizationServer, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "uma.resource", cfg->UmaResourceName, 0);
		Set_Ox_Storage(cfg->OpenIDClientName, "uma.rshost", cfg->uma_rs_host, 0);

		ret = false;
		goto EXIT_check_discovery_infos;
	}

EXIT_check_discovery_infos:
	if (oxdhost) free(oxdhost);
	if (discovery) free(discovery);
	if (redirect) free(redirect);
	if (clientname) free(clientname);
	if (creditpath) free(creditpath);
	if (uma_discovery) free(uma_discovery);
	if (uma_resource) free(uma_resource);
	if (uma_rshost) free(uma_rshost);

	return ret;
};

/*
* save session value after succeed in authorize.
*/
static int uma_set_cookie(request_rec *r, ox_cfg *cfg, opkele::params_t& params, std::string &session_id, int token_timeout)
{
	// now set auth cookie, if we're doing session based auth
	std::string hostname, path, cookie_value, id_token, access_token, scope, state, redirect_location, args;
	int expires_in;

	if(cfg->CookiePath != NULL) 
		path = std::string(cfg->CookiePath); 
	else 
		modox::base_dir(std::string(r->uri), path);

	if (params.has_param("state"))
		state = params.get_param("state");
	else
		return show_error(r, cfg, "error: unauthorized");

	if (params.has_param("expires_in"))
	{
		std::string expire_str = params.get_param("expires_in");
		expires_in = atoi(expire_str.c_str());
	} 
	else
	{
		expires_in = token_timeout;
	}

	modox::make_cookie_value(cookie_value, std::string(cfg->cookie_name), session_id, path, expires_in, false); 
	apr_table_set(r->err_headers_out, "Set-Cookie", cookie_value.c_str());
	hostname = std::string(r->hostname);

	// save session values
	std::string session_str = session_id + ";";
	session_str += hostname + ";";
	session_str += path + ";";
	session_str += "identity;";
	session_str += "username";
	Set_Ox_Storage(cfg->OpenIDClientName, session_id.c_str(), session_str.c_str(), expires_in);

	char *return_uri = Get_Ox_Storage(cfg->OpenIDClientName, state.c_str());
	if (return_uri == NULL)
		return show_error(r, cfg, "error: Incorrect return URI");

	r->args = NULL;

	redirect_location = return_uri;
	if (return_uri) free(return_uri);
	return modox::http_redirect(r, redirect_location);
};

/*
* start the process for authentication.
*/
static int uma_check_session(ox_cfg *cfg, const char *id_token, const char *session_id)
{
	return ox_check_id_token(cfg, id_token, session_id);
}

/*
* start the process for authentication.
*/
int uma_session(request_rec *r, ox_cfg *cfg, opkele::params_t& params) 
{
	int ret;
	bool info_changed = false;
	const apr_array_header_t    *fields;
	int                         i;
	apr_table_entry_t           *e = 0;

	modox::remove_openid_vars(params);

	ret = 0;
	if (check_discovery_infos(cfg) == true)	// unchanged
	{
		// Discovery & Register Client
		char *issuer = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.issuer");
		char *authorization_endpoint = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.authorization_endpoint");
		char *client_id = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.client_id");
		char *client_secret = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.client_secret");
		if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL) || (client_secret==NULL))
		{
			info_changed = true;
			ret = ox_discovery(cfg);
		}
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (client_id) free(client_id);
		if (client_secret) free(client_secret);
		if (ret < 0) return show_error(r, cfg, "oxd: UMA Discovery Failed");

		// Obtain PAT & Register Resource
		char *pat_token = Get_Ox_Storage(cfg->OpenIDClientName, "uma.pat_token");
		if (pat_token==NULL)
		{
			if (ox_obtain_pat(cfg) < 0) return show_error(r, cfg, "oxd: UMA obtain PAT Failed");
			if (ox_register_resources(cfg) < 0) return show_error(r, cfg, "oxd: UMA register Resource Failed");
		}
		else
		{
			free(pat_token);

			std::string id = std::string(cfg->UmaResourceName); id += "_id";
			std::string rev = std::string(cfg->UmaResourceName); rev += "_rev";
			char *resource_id = Get_Ox_Storage(cfg->OpenIDClientName, id.c_str());
			char *resource_rev = Get_Ox_Storage(cfg->OpenIDClientName, rev.c_str());
			
			if (!resource_id || !resource_rev)
				ret = ox_register_resources(cfg);

			if (resource_id) free(resource_id);
			if (resource_rev) free(resource_rev);
			if (ret < 0) return show_error(r, cfg, "oxd: UMA register Resource Failed");
		}

		// Obtain AAT Token
		char *aat_token = Get_Ox_Storage(cfg->OpenIDClientName, "uma.aat_token");
		if ((aat_token==NULL))
		{
			if (ox_obtain_aat(cfg) < 0) return show_error(r, cfg, "oxd: UMA obtain AAT Failed");
		}
		else
			free(aat_token);

		// 5. Obtain RPT Token
		char *rpt_token = Get_Ox_Storage(cfg->OpenIDClientName, "uma.rpt_token");
		if ((rpt_token==NULL))
		{
			if (ox_obtain_rpt(cfg) < 0) return show_error(r, cfg, "oxd: UMA obtain RPT Failed");
		}
		else
			free(rpt_token);
	} 
	else	// changed
	{
		info_changed = true;
		// Discovery & Register Client
		if (ox_discovery(cfg) < 0) return show_error(r, cfg, "oxd: UMA discovery Failed");
		// Obtain PAT
		if (ox_obtain_pat(cfg) < 0) return show_error(r, cfg, "oxd: UMA obtain PAT Failed");
		// Register Resource
		if (ox_register_resources(cfg) < 0) return show_error(r, cfg, "oxd: UMA register Resource Failed");
		// Obtain AAT
		if (ox_obtain_aat(cfg) < 0) return show_error(r, cfg, "oxd: UMA obtain AAT Failed");
		// Obtain RPT
		if (ox_obtain_rpt(cfg) < 0) return show_error(r, cfg, "oxd: UMA obtain RPT Failed");
	}

	char *issuer = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.issuer");
	char *authorization_endpoint = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.authorization_endpoint");
	char *client_id = Get_Ox_Storage(cfg->OpenIDClientName, "oxd.client_id");

	if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL))
	{
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (client_id) free(client_id);

		return show_error(r, cfg, "oxd: UMA discovery Failed");
	}

	std::string identity = std::string(issuer);
	APDEBUG(r, "identity = %s", issuer);

	// add a nonce and reset what return_to is
	std::string nonce;
	modox::make_rstring(10, nonce);
	params["nonce"] = nonce;

	std::string state;
	modox::make_rstring(10, state);
	params["state"] = state;
	if(params.has_param("target")) 
	{
		Set_Ox_Storage(cfg->OpenIDClientName, state.c_str(), params.get_param("target").c_str(), 0);
	}
	else
	{
		std::string target_location;
		if (cfg->ApplicationDestinationUrl)
		{
			Set_Ox_Storage(cfg->OpenIDClientName, state.c_str(), cfg->ApplicationDestinationUrl, 0);
		} 
		else
		{
			full_uri(r, target_location, cfg, r->uri);
			Set_Ox_Storage(cfg->OpenIDClientName, state.c_str(), target_location.c_str(), 0);
		}
	}

	// build Redirect parameters
	if (client_id) params["client_id"] = client_id;
	params["response_type"] = "token id_token";
	params["scope"] = "openid profile address email";

	params["redirect_uri"] = cfg->OpenIDClientRedirectURIs;
	if (cfg->SendHeaders == SETON)
	{
		fields = apr_table_elts(r->headers_in);
		e = (apr_table_entry_t *) fields->elts;
		for(i = 0; i < fields->nelts; i++) {
			params[e[i].key] = e[i].val;
		}
	}

	std::string auth_end = std::string(authorization_endpoint);

	return modox::http_redirect(r, params.append_query(auth_end, "")); 
};

/*
* check to has session for uma
*/
int has_uma_session(request_rec *r, ox_cfg *cfg, opkele::params_t& params, int log_out)
{
	// test for valid session
	std::string session_id = "";
	std::string session_value = "";
	if (cfg->cookie_name != NULL)
		modox::get_session_id(r, std::string(cfg->cookie_name), session_id, session_value);
	if(session_id != "")
	{ // Found Session ID
		modox::debug("found session_id in cookie: " + session_id);
		modox::session_t session;

		// Get Session String
		char *session_str = Get_Ox_Storage(cfg->OpenIDClientName, session_value.c_str());
		if (!session_str)
			goto EXIT_has_uma_session;

		if (log_out)
		{
			char id_token[1024] = "";
			modox::debug("deleting session: " + session_id);

			char *id_token_str = Get_Ox_Storage(session_value.c_str(), "id_token");
			if (id_token_str != NULL)
				strcpy(id_token, id_token_str);
			free(id_token_str);
			Remove_Ox_Storage(cfg->OpenIDClientName, session_value.c_str());
			apr_table_clear(r->subprocess_env);
			Remove_Ox_Storage(session_value.c_str(), "session_id");
			Remove_Ox_Storage(session_value.c_str(), "id_token");
			Remove_Ox_Storage(session_value.c_str(), "access_token");
			Remove_Ox_Storage(session_value.c_str(), "scope");
			Remove_Ox_Storage(session_value.c_str(), "state");
			Remove_Ox_Storage(cfg->OpenIDClientName, session_id.c_str());

			if (session_str) free(session_str);

			params.clear();
			if (cfg->ApplicationPostLogoutUrl)
			{
				params["id_token_hint"] = id_token;
				if (cfg->ApplicationPostLogoutRedirectUrl != NULL)
					params["post_logout_redirect_uri"] = cfg->ApplicationPostLogoutRedirectUrl;
				else
					params["post_logout_redirect_uri"] = "";
				std::string redirect_end = std::string(cfg->ApplicationPostLogoutUrl);
				return modox::http_redirect(r, params.append_query(redirect_end, ""));
			}

			return -1;
		}

		char *ptr6, *ptr7, *ptr8, *ptr9, *ptr10;
		ptr6 = strtok(session_str, ";");
		ptr7 = strtok(NULL, ";");
		ptr8 = strtok(NULL, ";");
		ptr9 = strtok(NULL, ";");
		ptr10 = strtok(NULL, ";");
		if (!ptr6 || !ptr7 || !ptr8 || !ptr9 || !ptr10)
		{
			free(session_str);
			goto EXIT_has_uma_session;
		}

		session.session_id = std::string(ptr6);
		session.hostname = std::string(ptr7);
		session.path = std::string(ptr8);
		session.identity = std::string(ptr9);
		session.username = std::string(ptr10);

		// if session found 
		if(session.identity != "") 
		{
			std::string uri_path(r->uri);
			//modox::base_dir(std::string(r->uri), uri_path);
			std::string valid_path(session.path);
			// if found session has a valid path
			if((valid_path==uri_path.substr(0, valid_path.size()) ||
				((((uri_path.size()+1)==valid_path.size())) && (strncasecmp(uri_path.c_str(), valid_path.c_str(), uri_path.size()) == 0)))
				&& strcasecmp(session.hostname.c_str(), r->hostname)==0) 
			{
				const char* idchar = session.identity.c_str();
				r->user = apr_pstrdup(r->pool, idchar);
				if (session_str) free(session_str);

				// set environment variable
				// SESSION_ID
				char *session_id_str = Get_Ox_Storage(session_value.c_str(), "session_id");
				if (session_id_str)
				{
					apr_table_set(r->subprocess_env, "OIC_SESSION_ID", session_id_str);
					apr_table_set(r->headers_in, "OIC_SESSION_ID", session_id_str);
					apr_table_set(r->err_headers_out, "OIC_SESSION_ID", session_id_str);
					free(session_id_str);
				}

				// ID_TOKEN
				char *id_token_str = Get_Ox_Storage(session_value.c_str(), "id_token");
				if (id_token_str)
				{
					apr_table_set(r->subprocess_env, "OIC_ID_TOKEN", id_token_str);
					apr_table_set(r->headers_in, "OIC_ID_TOKEN", id_token_str);
					apr_table_set(r->err_headers_out, "OIC_ID_TOKEN", id_token_str);
					free(id_token_str);
				}

				// ACCESS TOKEN
				char *access_token_str = Get_Ox_Storage(session_value.c_str(), "access_token");
				if (access_token_str)
				{
					apr_table_set(r->subprocess_env, "OIC_ACCESS_TOKEN", access_token_str);
					apr_table_set(r->headers_in, "OIC_ACCESS_TOKEN", access_token_str);
					apr_table_set(r->err_headers_out, "OIC_ACCESS_TOKEN", access_token_str);
					free(access_token_str);
				}

				// SCOPE
				char *scope_str = Get_Ox_Storage(session_value.c_str(), "scope");
				if (scope_str)
				{
					apr_table_set(r->subprocess_env, "OIC_SCOPE", scope_str);
					apr_table_set(r->headers_in, "OIC_SCOPE", scope_str);
					apr_table_set(r->err_headers_out, "OIC_SCOPE", scope_str);
					free(scope_str);
				}

				// STATE
				char *state_str = Get_Ox_Storage(session_value.c_str(), "state");
				char state[128];
				if (state_str)
				{
					strcpy(state, state_str);
					apr_table_set(r->subprocess_env, "OIC_STATE", state_str);
					apr_table_set(r->headers_in, "OIC_STATE", state_str);
					apr_table_set(r->err_headers_out, "OIC_STATE", state_str);
					free(state_str);
				}

				return 1;
			} 
			else 
			{
				APDEBUG(r, "session found for different path or hostname (cookie was for %s)", session.hostname.c_str());
			}
		}

		if (session_str) free(session_str);
	}

EXIT_has_uma_session:
	if(params.has_param("id_token") && params.has_param("access_token")) 
	{
		// user has been redirected, authenticate that and set cookie
		return 0;
	}
	else if(params.has_param("code") && params.has_param("state")) 
	{
		// user has been redirected, authenticate that and set cookie
		return 0;
	}


	return -1;
};

/*
* check the validation of session
*/
int validate_uma_session(request_rec *r, ox_cfg *cfg, opkele::params_t& params) 
{
	std::string session_id, session_tmp;
	int token_timeout;
	int time_out;

	if (params.has_param("session_id"))
		session_tmp = params.get_param("session_id");
	else
		modox::make_rstring(32, session_tmp);

	std::string id_token;
	if (params.has_param("id_token"))
		id_token = params.get_param("id_token");
	else
		return show_error(r, cfg, "error: unauthorized");

	// Get state from params
	std::string state;
	if (params.has_param("state"))
		state = params.get_param("state");
	else
		return show_error(r, cfg, "error: unauthorized");

	// Get scope from params
	std::string scope;
	if (params.has_param("scope"))
		scope = params.get_param("scope");
	else
		return show_error(r, cfg, "error: unauthorized");

	// Get access token from params
	std::string access_token;
	if (params.has_param("access_token"))
		access_token = params.get_param("access_token");
	else
		return show_error(r, cfg, "error: unauthorized");

	// Get expires_in from params
	std::string expires_in;
	if (params.has_param("expires_in"))
		expires_in = params.get_param("expires_in");
	else
		return show_error(r, cfg, "error: unauthorized");

	time_out = (int)atoi(expires_in.c_str());

	// session_id = session_id+"."+state
	session_id = session_tmp+"."+state;

	token_timeout = uma_check_session(cfg, id_token.c_str(), session_id.c_str());
	if (token_timeout <= 0)
		return show_error(r, cfg, "oxd: UMA check session Failed");

	if (ox_obtain_rpt(cfg) < 0)
		return HTTP_FORBIDDEN;

	if (ox_register_ticket(cfg) < 0)
		return HTTP_FORBIDDEN;

	if (ox_authorize_rpt(cfg, session_tmp.c_str()) < 0)
		return HTTP_FORBIDDEN;

	if (ox_check_rpt_status(cfg) < 0)
		return HTTP_FORBIDDEN;

	// Save paraams into memcached
	Set_Ox_Storage(session_id.c_str(), "session_id", session_tmp.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_SESSION_ID", session_tmp.c_str());

	Set_Ox_Storage(session_id.c_str(), "id_token", id_token.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_ID_TOKEN", id_token.c_str());

	Set_Ox_Storage(session_id.c_str(), "access_token", access_token.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_ACCESS_TOKEN", access_token.c_str());

	Set_Ox_Storage(session_id.c_str(), "scope", scope.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_SCOPE", scope.c_str());

	Set_Ox_Storage(session_id.c_str(), "state", state.c_str(), time_out);
	apr_table_set(r->headers_out, "OIC_STATE", state.c_str());

	return set_uma_cookie(r, cfg, params, session_id, token_timeout);
};