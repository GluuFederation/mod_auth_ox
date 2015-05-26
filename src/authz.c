/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2013-2015 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * mostly copied from mod_auth_cas
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>

#include "mod_auth_ox.h"

#include <pcre.h>

static apr_byte_t ox_authz_match_value(request_rec *r, const char *spec_c,
		json_t *val, const char *key) {

	int i = 0;

	/* see if it is a string and it (case-insensitively) matches the Require'd value */
	if (json_is_string(val)) {

		if (apr_strnatcmp(json_string_value(val), spec_c) == 0)
			return TRUE;

		/* see if it is a integer and it equals the Require'd value */
	} else if (json_is_integer(val)) {

		if (json_integer_value(val) == atoi(spec_c))
			return TRUE;

		/* see if it is a boolean and it (case-insensitively) matches the Require'd value */
	} else if (json_is_boolean(val)) {

		if (apr_strnatcmp(json_is_true(val) ? "true" : "false", spec_c) == 0)
			return TRUE;

		/* if it is an array, we'll walk it */
	} else if (json_is_array(val)) {

		/* compare the claim values */
		for (i = 0; i < json_array_size(val); i++) {

			json_t *elem = json_array_get(val, i);

			if (json_is_string(elem)) {
				/*
				 * approximately compare the claim value (ignoring
				 * whitespace). At this point, spec_c points to the
				 * NULL-terminated value pattern.
				 */
				if (apr_strnatcmp(json_string_value(elem), spec_c) == 0)
					return TRUE;

			} else if (json_is_boolean(elem)) {

				if (apr_strnatcmp(
				json_is_true(elem) ? "true" : "false", spec_c) == 0)
					return TRUE;

			} else if (json_is_integer(elem)) {

				if (json_integer_value(elem) == atoi(spec_c))
					return TRUE;

			} else {

				ox_warn(r,
						"unhandled in-array JSON object type [%d] for key \"%s\"",
						elem->type, (const char * ) key);
			}

		}

	} else {
		ox_warn(r, "unhandled JSON object type [%d] for key \"%s\"",
				val->type, (const char * ) key);
	}

	return FALSE;
}

static bool ox_check_discovery_infos(mod_ox_config *s_cfg)
{
	bool ret = true;

	char *oxdhost = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.oxdhost");
	char *discovery = Get_Ox_Storage(s_cfg->OpenIDClientName, "connect.discovery");
	char *redirect = Get_Ox_Storage(s_cfg->OpenIDClientName, "connect.redirect");
	char *clientname = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.clientname");
	char *creditpath = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.creditpath");

	if (!oxdhost || !discovery || !redirect || !clientname || (!creditpath && s_cfg->ClientCredsPath))
	{
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.oxdhost", s_cfg->OxdHostAddr, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.discovery", s_cfg->OpenIDProvider, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.redirect", s_cfg->OpenIDClientRedirectURIs, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.clientname", s_cfg->OpenIDClientName, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.creditpath", s_cfg->ClientCredsPath, 0);

		ret = false; 
		goto EXIT_check_discovery_infos;
	}

	if (strcmp(oxdhost, s_cfg->OxdHostAddr) ||
		strcmp(discovery, s_cfg->OpenIDProvider) ||
		strcmp(redirect, s_cfg->OpenIDClientRedirectURIs) ||
		strcmp(clientname, s_cfg->OpenIDClientName) || 
		(s_cfg->ClientCredsPath && strcmp(creditpath, s_cfg->ClientCredsPath)))
	{
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.oxdhost", s_cfg->OxdHostAddr, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.discovery", s_cfg->OpenIDProvider, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "connect.redirect", s_cfg->OpenIDClientRedirectURIs, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.clientname", s_cfg->OpenIDClientName, 0);
		Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.creditpath", s_cfg->ClientCredsPath, 0);

		ret = false;
		goto EXIT_check_discovery_infos;
	}

EXIT_check_discovery_infos:
	if (oxdhost) free(oxdhost);
	if (discovery) free(discovery);
	if (redirect) free(redirect);
	if (clientname) free(clientname);
	if (creditpath) free(creditpath);

	return ret;
};

static int ox_set_connect_cookie(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params, std::string &session_id, int token_timeout)
 {
	// now set auth cookie, if we're doing session based auth
	std::string hostname, path, cookie_value, id_token, access_token, scope, state, redirect_location, args;
	int expires_in;

	if(s_cfg->CookiePath != NULL) 
		path = std::string(s_cfg->CookiePath); 
	else 
		modox::base_dir(std::string(r->unparsed_uri), path);

	if (params.has_param("state"))
		state = params.get_param("state");
	else
		return show_error(r, s_cfg, "error: unauthorized");

	if (params.has_param("expires_in"))
	{
		std::string expire_str = params.get_param("expires_in");
		expires_in = atoi(expire_str.c_str());
	} 
	else
	{
		expires_in = token_timeout;
	}

	modox::make_cookie_value(cookie_value, std::string(s_cfg->cookie_name), session_id, path, expires_in, false); 
	apr_table_set(r->err_headers_out, "Set-Cookie", cookie_value.c_str());
	hostname = std::string(r->hostname);

	// save session values
	std::string session_str = session_id + ";";
	session_str += hostname + ";";
	session_str += path + ";";
	session_str += "identity;";
	session_str += "username";
	Set_Ox_Storage(s_cfg->OpenIDClientName, session_id.c_str(), session_str.c_str(), expires_in);

	char *return_uri = Get_Ox_Storage(s_cfg->OpenIDClientName, state.c_str());
	if (return_uri == NULL)
		return show_error(r, s_cfg, "error: Incorrect return URI");

	r->args = NULL;

	redirect_location = return_uri;
	if (return_uri) free(return_uri);
	return modox::http_redirect(r, redirect_location);
};

/*
* start the process for authentication.
*/
static int ox_check_session(mod_ox_config *s_cfg, const char *id_token, const char *session_id)
{
	return ox_check_id_token(s_cfg, id_token, session_id);
}

/*
* start the process for authentication.
*/
int ox_start_connect_session(request_rec *r, mod_ox_config *s_cfg, opkele::params_t& params) 
{
	unsigned i;
	int ret;
	bool info_changed = false;
	const apr_array_header_t    *fields;
	apr_table_entry_t           *e = 0;

	modox::remove_openid_vars(params);

	ret = 0;
	if (check_discovery_infos(s_cfg) == true)	// unchanged
	{
		// Discovery & Register Client
		char *issuer = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.issuer");
		char *authorization_endpoint = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.authorization_endpoint");
		char *token_endpoint = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.token_endpoint");
		char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
		char *client_secret = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret");
		if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL) || (client_secret==NULL))
		{
			info_changed = true;
			ret = ox_discovery(s_cfg);
		}
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (token_endpoint) free(token_endpoint);
		if (client_id) free(client_id);
		if (client_secret) free(client_secret);
		if (ret < 0) return show_error(r, s_cfg, "oxd: OpenID Connect Discovery Failed");
	} 
	else	// changed
	{
		info_changed = true;
		// Discovery & Register Client
		if (ox_discovery(s_cfg) < 0) return show_error(r, s_cfg, "oxd: OpenID Connect Discovery Failed");
	}

	char *issuer = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.issuer");
	char *authorization_endpoint = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.authorization_endpoint");
	char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");

	if ((issuer==NULL) || (authorization_endpoint==NULL) || (client_id==NULL))
	{
		if (issuer) free(issuer);
		if (authorization_endpoint) free(authorization_endpoint);
		if (client_id) free(client_id);

		return show_error(r, s_cfg, "oxd: OpenID Connect Discovery Failed");
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
		Set_Ox_Storage(s_cfg->OpenIDClientName, state.c_str(), params.get_param("target").c_str(), 0);
	}
	else
	{
		std::string target_location;
		if (s_cfg->ApplicationDestinationUrl)
		{
			Set_Ox_Storage(s_cfg->OpenIDClientName, state.c_str(), s_cfg->ApplicationDestinationUrl, 0);
		} 
		else
		{
			full_uri(r, target_location, s_cfg, r->uri);
			Set_Ox_Storage(s_cfg->OpenIDClientName, state.c_str(), target_location.c_str(), 0);
		}
	}

	// build Redirect parameters
	std::string origin_headers = "{";
	// send headers
	if (s_cfg->SendHeaders == SETON)
	{
		fields = apr_table_elts(r->headers_in);
		e = (apr_table_entry_t *) fields->elts;
		if (fields->nelts > 0)
		{
			for(i = 0; i < (unsigned)(fields->nelts-1); i++) {
				origin_headers += "\"";
				origin_headers += e[i].key;
				origin_headers += "\":\"";
				origin_headers += e[i].val;
				origin_headers += "\",";
			}
			origin_headers += "\"";
			origin_headers += e[i].key;
			origin_headers += "\":\"";
			origin_headers += e[i].val;
			origin_headers += "\"}";
			params["origin_headers"] = origin_headers;
		}
	}

	if (client_id) params["client_id"] = client_id;
	if (s_cfg->OpenIDResponseType) params["response_type"] = s_cfg->OpenIDResponseType;
	
	std::string scope;
	std::vector<std::string> scope_pairs = modox::explode(s_cfg->OpenIDRequestedScopes, ";");
	for(i=0; i<scope_pairs.size()-1; i++)
	{
		scope += scope_pairs[i];
		scope += " ";
	}
	scope += scope_pairs[i];
	params["scope"] = scope;

	params["redirect_uri"] = s_cfg->OpenIDClientRedirectURIs;
/*
	std::string requested_acr = "\"";
	std::vector<std::string> acr_pairs = modox::explode(s_cfg->OpenIDRequestedACR, ";");
	for(i=0; i<acr_pairs.size()-1; i++)
	{
		requested_acr += acr_pairs[i];
		requested_acr += "\",\"";
	}
	requested_acr += acr_pairs[i];
	requested_acr += "\"";
	if (s_cfg->OpenIDRequestedACR) params["acr_values"] = requested_acr;
*/	
	std::string auth_end = std::string(authorization_endpoint);

	if (issuer) free(issuer);
	if (authorization_endpoint) free(authorization_endpoint);
	if (client_id) free(client_id);

	// Redirect to seed.gluu.org
	return modox::http_redirect(r, params.append_query(auth_end, ""));
};

static apr_byte_t ox_authz_match_expression(request_rec *r,
		const char *spec_c, json_t *val) {
	const char *errorptr;
	int erroffset;
	pcre *preg;
	int i = 0;

	/* setup the regex; spec_c points to the NULL-terminated value pattern */
	preg = pcre_compile(spec_c, 0, &errorptr, &erroffset, NULL);

	if (preg == NULL) {
		ox_error(r, "pattern [%s] is not a valid regular expression", spec_c);
		pcre_free(preg);
		return FALSE;
	}

	/* see if the claim is a literal string */
	if (json_is_string(val)) {

		/* PCRE-compare the string value against the expression */
		if (pcre_exec(preg, NULL, json_string_value(val),
				(int) strlen(json_string_value(val)), 0, 0, NULL, 0) == 0) {
			pcre_free(preg);
			return TRUE;
		}

		/* see if the claim value is an array */
	} else if (json_is_array(val)) {

		/* compare the claim values in the array against the expression */
		for (i = 0; i < json_array_size(val); i++) {

			json_t *elem = json_array_get(val, i);
			if (json_is_string(elem)) {

				/* PCRE-compare the string value against the expression */
				if (pcre_exec(preg, NULL, json_string_value(elem),
						(int) strlen(json_string_value(elem)), 0, 0,
						NULL, 0) == 0) {
					pcre_free(preg);
					return TRUE;
				}
			}
		}
	}

	pcre_free(preg);

	return FALSE;
}

/*
 * see if a the Require value matches with a set of provided claims
 */
static apr_byte_t ox_authz_match_claim(request_rec *r,
		const char * const attr_spec, const json_t * const claims) {

	const char *key;
	json_t *val;

	/* if we don't have any claims, they can never match any Require claim primitive */
	if (claims == NULL)
		return FALSE;

	/* loop over all of the user claims */
	void *iter = json_object_iter((json_t*) claims);
	while (iter) {

		key = json_object_iter_key(iter);
		val = json_object_iter_value(iter);

		ox_debug(r, "evaluating key \"%s\"", (const char * ) key);

		const char *attr_c = (const char *) key;
		const char *spec_c = attr_spec;

		/* walk both strings until we get to the end of either or we find a differing character */
		while ((*attr_c) && (*spec_c) && (*attr_c) == (*spec_c)) {
			attr_c++;
			spec_c++;
		}

		/* The match is a success if we walked the whole claim name and the attr_spec is at a colon. */
		if (!(*attr_c) && (*spec_c) == ':') {

			/* skip the colon */
			spec_c++;

			if (ox_authz_match_value(r, spec_c, val, key) == TRUE)
				return TRUE;

			/* a tilde denotes a string PCRE match */
		} else if (!(*attr_c) && (*spec_c) == '~') {

			/* skip the tilde */
			spec_c++;

			if (ox_authz_match_expression(r, spec_c, val) == TRUE)
				return TRUE;
		}

		iter = json_object_iter_next((json_t *) claims, iter);
	}

	return FALSE;
}

/*
 * Apache <2.4 authorization routine: match the claims from the authenticated user against the Require primitive
 */
int ox_authz_worker(request_rec *r, const json_t * const claims,
		const require_line * const reqs, int nelts) {
	const int m = r->method_number;
	const char *token;
	const char *requirement;
	int i;
	int have_oauthattr = 0;
	int count_oauth_claims = 0;

	/* go through applicable Require directives */
	for (i = 0; i < nelts; ++i) {

		/* ignore this Require if it's in a <Limit> section that exclude this method */
		if (!(reqs[i].method_mask & (AP_METHOD_BIT << m))) {
			continue;
		}

		/* ignore if it's not a "Require claim ..." */
		requirement = reqs[i].requirement;

		token = ap_getword_white(r->pool, &requirement);

		if (apr_strnatcasecmp(token, OX_REQUIRE_NAME) != 0) {
			continue;
		}

		/* ok, we have a "Require claim" to satisfy */
		have_oauthattr = 1;

		/*
		 * If we have an applicable claim, but no claims were sent in the request, then we can
		 * just stop looking here, because it's not satisfiable. The code after this loop will
		 * give the appropriate response.
		 */
		if (!claims) {
			break;
		}

		/*
		 * iterate over the claim specification strings in this require directive searching
		 * for a specification that matches one of the claims.
		 */
		while (*requirement) {
			token = ap_getword_conf(r->pool, &requirement);
			count_oauth_claims++;

			ox_debug(r, "evaluating claim specification: %s", token);

			if (ox_authz_match_claim(r, token, claims) == TRUE) {

				/* if *any* claim matches, then authorization has succeeded and all of the others are ignored */
				ox_debug(r, "require claim '%s' matched", token);
				return OK;
			}
		}
	}

	/* if there weren't any "Require claim" directives, we're irrelevant */
	if (!have_oauthattr) {
		ox_debug(r, "no claim statements found, not performing authz");
		return DECLINED;
	}
	/* if there was a "Require claim", but no actual claims, that's cause to warn the admin of an iffy configuration */
	if (count_oauth_claims == 0) {
		ox_warn(r,
				"'require claim' missing specification(s) in configuration, declining");
		return DECLINED;
	}

	/* log the event, also in Apache speak */
	ox_debug(r, "authorization denied for client session");
	ap_note_auth_failure(r);

	return HTTP_UNAUTHORIZED;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
/*
 * Apache >=2.4 authorization routine: match the claims from the authenticated user against the Require primitive
 */
authz_status ox_authz_worker24(request_rec *r, const json_t * const claims, const char *require_args) {

	int count_oauth_claims = 0;
	const char *t, *w;

	/* needed for anonymous authentication */
	if (r->user == NULL) return AUTHZ_DENIED_NO_USER;

	/* if no claims, impossible to satisfy */
	if (!claims) return AUTHZ_DENIED;

	/* loop over the Required specifications */
	t = require_args;
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {

		count_oauth_claims++;

		ox_debug(r, "evaluating claim specification: %s", w);

		/* see if we can match any of out input claims against this Require'd value */
		if (ox_authz_match_claim(r, w, claims) == TRUE) {

			ox_debug(r, "require claim '%s' matched", w);
			return AUTHZ_GRANTED;
		}
	}

	/* if there wasn't anything after the Require claims directive... */
	if (count_oauth_claims == 0) {
		ox_warn(r,
				"'require claim' missing specification(s) in configuration, denying");
	}

	return AUTHZ_DENIED;
}
#endif
