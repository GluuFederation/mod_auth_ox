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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <apr_lib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_auth_ox.h"

#ifdef WIN32
extern "C" module AP_MODULE_DECLARE_DATA auth_ox_module;
#else
extern module AP_MODULE_DECLARE_DATA auth_ox_module;
#endif

/*
 * validate an access token against the validation endpoint of the Authorization server and gets a response back
 */
static apr_byte_t ox_oauth_validate_access_token(request_rec *r, ox_cfg *c,
		const char *token, const char **response) {

	/* get a handle to the directory config */
	ox_dir_cfg *dir_cfg = (ox_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	/* assemble parameters to call the token endpoint for validation */
	apr_table_t *params = apr_table_make(r->pool, 4);

	/* add any configured extra static parameters to the introspection endpoint */
	ox_util_table_add_query_encoded_params(r->pool, params,
			c->oauth.introspection_endpoint_params);

	/* add the access_token itself */
	apr_table_addn(params, c->oauth.introspection_token_param_name, token);

	/* see if we want to do basic auth or post-param-based auth */
	const char *basic_auth = NULL;
	if ((c->oauth.client_id != NULL) && (c->oauth.client_secret != NULL)) {
		if ((c->oauth.introspection_endpoint_auth != NULL)
				&& (apr_strnatcmp(c->oauth.introspection_endpoint_auth,
						"client_secret_post") == 0)) {
			apr_table_addn(params, "client_id", c->oauth.client_id);
			apr_table_addn(params, "client_secret", c->oauth.client_secret);
		} else {
			basic_auth = apr_psprintf(r->pool, "%s:%s", c->oauth.client_id,
					c->oauth.client_secret);
		}
	}

	/* call the endpoint with the constructed parameter set and return the resulting response */
	return apr_strnatcmp(c->oauth.introspection_endpoint_method, "GET") == 0 ?
			ox_util_http_get(r, c->oauth.introspection_endpoint_url, params,
					basic_auth, NULL, c->oauth.ssl_validate_server, response,
					c->http_timeout_long, c->outgoing_proxy,
					dir_cfg->pass_cookies) :
			ox_util_http_post_form(r, c->oauth.introspection_endpoint_url,
					params, basic_auth, NULL, c->oauth.ssl_validate_server,
					response, c->http_timeout_long, c->outgoing_proxy,
					dir_cfg->pass_cookies);
}

static apr_byte_t uma_oauth_validate_access_token(request_rec *r, ox_cfg *c,
		const char *token, const char **response) {

	/* get a handle to the directory config */
	uma_dir_cfg *dir_cfg = (uma_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	/* assemble parameters to call the token endpoint for validation */
	apr_table_t *params = apr_table_make(r->pool, 4);

	/* add any configured extra static parameters to the introspection endpoint */
	ox_util_table_add_query_encoded_params(r->pool, params,
			c->oauth.introspection_endpoint_params);

	/* add the access_token itself */
	apr_table_addn(params, c->oauth.introspection_token_param_name, token);

	/* see if we want to do basic auth or post-param-based auth */
	const char *basic_auth = NULL;
	if ((c->oauth.client_id != NULL) && (c->oauth.client_secret != NULL)) {
		if ((c->oauth.introspection_endpoint_auth != NULL)
				&& (apr_strnatcmp(c->oauth.introspection_endpoint_auth,
						"client_secret_post") == 0)) {
			apr_table_addn(params, "client_id", c->oauth.client_id);
			apr_table_addn(params, "client_secret", c->oauth.client_secret);
		} else {
			basic_auth = apr_psprintf(r->pool, "%s:%s", c->oauth.client_id,
					c->oauth.client_secret);
		}
	}

	/* call the endpoint with the constructed parameter set and return the resulting response */
	return apr_strnatcmp(c->oauth.introspection_endpoint_method, "GET") == 0 ?
			ox_util_http_get(r, c->oauth.introspection_endpoint_url, params,
					dir_cfg->pass_cookies) :
			ox_util_http_post_form(r, c->oauth.introspection_endpoint_url,
					params, basic_auth, NULL, c->oauth.ssl_validate_server,
					dir_cfg->pass_cookies);
}

/*
 * get the authorization header that should contain a bearer token
 */
static apr_byte_t ox_oauth_get_bearer_token(request_rec *r,
		const char **access_token) {

	/* get the authorization header */
	const char *auth_line;
	auth_line = apr_table_get(r->headers_in, "Authorization");
	if (!auth_line) {
		ox_debug(r, "no authorization header found");
		return FALSE;
	}

	/* look for the Bearer keyword */
	if (apr_strnatcasecmp(ap_getword(r->pool, &auth_line, ' '), "Bearer")) {
		ox_error(r, "client used unsupported authentication scheme: %s",
				r->uri);
		return FALSE;
	}

	/* skip any spaces after the Bearer keyword */
	while (apr_isspace(*auth_line)) {
		auth_line++;
	}

	/* copy the result in to the access_token */
	*access_token = apr_pstrdup(r->pool, auth_line);

	/* log some stuff */
	ox_debug(r, "bearer token: %s", *access_token);

	return TRUE;
}

static apr_byte_t uma_oauth_get_bearer_token(request_rec *r,
		const char **access_token) {

	/* get the authorization header */
	const char *auth_line;
	auth_line = apr_table_get(r->headers_in, "Authorization");
	if (!auth_line) {
		ox_debug(r, "no authorization header found");
		return FALSE;
	}

	/* look for the Bearer keyword */
	if (apr_strnatcasecmp(ap_getword(r->pool, &auth_line, ' '), "Bearer")) {
		ox_error(r, "client used unsupported authentication scheme: %s",
				r->uri);
		return FALSE;
	}

	/* skip any spaces after the Bearer keyword */
	while (apr_isspace(*auth_line)) {
		auth_line++;
	}

	/* copy the result in to the access_token */
	*access_token = apr_pstrdup(r->pool, auth_line);
	session_token = apr_pstrdup(r->pool, session_line);

	/* log some stuff */
	ox_debug(r, "bearer token: %s", *access_token);

	return TRUE;
}

/*
 * copy over space separated scope value but do it in an array for authorization purposes
 */
/*
static void ox_oauth_spaced_string_to_array(request_rec *r, json_t *src,
		const char *src_key, json_t *dst, const char *dst_key) {
	apr_hash_t *ht = NULL;
	apr_hash_index_t *hi = NULL;
	json_t *arr = NULL;

	json_t *src_val = json_object_get(src, src_key);

	if (src_val != NULL)
		ht = ox_util_spaced_string_to_hashtable(r->pool,
				json_string_value(src_val));

	if (ht != NULL) {
		arr = json_array();
		for (hi = apr_hash_first(NULL, ht); hi; hi = apr_hash_next(hi)) {
			const char *k;
			const char *v;
			apr_hash_this(hi, (const void**) &k, NULL, (void**) &v);
			json_array_append_new(arr, json_string(v));
		}
		json_object_set_new(dst, dst_key, arr);
	}
}
*/

/*
 * parse (custom/configurable) token expiry claim in introspection result
 */
static apr_byte_t ox_oauth_parse_and_cache_token_expiry(request_rec *r,
		ox_cfg *c, json_t *introspection_response,
		const char *expiry_claim_name, int expiry_format_absolute,
		int expiry_claim_is_mandatory, apr_time_t *cache_until) {

	ox_debug(r, "expiry_claim_name=%s, expiry_format_absolute=%d, expiry_claim_is_mandatory=%d", expiry_claim_name, expiry_format_absolute, expiry_claim_is_mandatory);

	json_t *expiry = json_object_get(introspection_response, expiry_claim_name);

	if (expiry == NULL) {
		if (expiry_claim_is_mandatory) {
			ox_error(r,
					"introspection response JSON object did not contain an \"%s\" claim",
					expiry_claim_name);
			return FALSE;
		}
		return TRUE;
	}

	if (!json_is_integer(expiry)) {
		if (expiry_claim_is_mandatory) {
			ox_error(r,
					"introspection response JSON object contains a \"%s\" claim but it is not a JSON integer",
					expiry_claim_name);
			return FALSE;
		}
		ox_warn(r,
				"introspection response JSON object contains a \"%s\" claim that is not an (optional) JSON integer: the introspection result will NOT be cached",
				expiry_claim_name);
		return TRUE;
	}

	json_int_t value = json_integer_value(expiry);
	if (value <= 0) {
		ox_warn(r,
				"introspection response JSON object integer number value <= 0 (%" JSON_INTEGER_FORMAT "); introspection result will not be cached",
				value);
		return TRUE;
	}

	*cache_until = apr_time_from_sec(value);
	if (expiry_format_absolute == FALSE)
		(*cache_until) += apr_time_now();

	return TRUE;
}

/*
 * resolve and validate an access_token against the configured Authorization Server
 */
static apr_byte_t ox_oauth_resolve_access_token(request_rec *r, ox_cfg *c,
		const char *access_token, json_t **token, char **response) {

	json_t *result = NULL;
	const char *json = NULL;

	/* see if we've got the claims for this access_token cached already */
	c->cache->get(r, OX_CACHE_SECTION_ACCESS_TOKEN, access_token, &json);

	if (json == NULL) {

		/* not cached, go out and validate the access_token against the Authorization server and get the JSON claims back */
		if (ox_oauth_validate_access_token(r, c, access_token, &json) == FALSE) {
			ox_error(r,
					"could not get a validation response from the Authorization server");
			return FALSE;
		}

		/* decode and see if it is not an error response somehow */
		if (ox_util_decode_json_and_check_error(r, json, &result) == FALSE)
			return FALSE;

		json_t *active = json_object_get(result, "active");
		apr_time_t cache_until;
		if (active != NULL) {

			if ((!json_is_boolean(active)) || (!json_is_true(active))) {
				ox_debug(r,
						"no \"active\" boolean object with value \"true\" found in response JSON object");
				json_decref(result);
				return FALSE;
			}

			if (ox_oauth_parse_and_cache_token_expiry(r, c, result, "exp",
					TRUE, FALSE, &cache_until) == FALSE) {
				json_decref(result);
				return FALSE;
			}

			/* set it in the cache so subsequent request don't need to validate the access_token and get the claims anymore */
			c->cache->set(r, OX_CACHE_SECTION_ACCESS_TOKEN, access_token,
					json, cache_until);

		} else {

			if (ox_oauth_parse_and_cache_token_expiry(r, c, result,
					c->oauth.introspection_token_expiry_claim_name,
					apr_strnatcmp(
							c->oauth.introspection_token_expiry_claim_format,
							"absolute") == 0,
							c->oauth.introspection_token_expiry_claim_required,
							&cache_until) == FALSE) {
				json_decref(result);
				return FALSE;
			}

			/* set it in the cache so subsequent request don't need to validate the access_token and get the claims anymore */
			c->cache->set(r, OX_CACHE_SECTION_ACCESS_TOKEN, access_token,
					json, cache_until);

		}

	} else {

		/* we got the claims for this access_token in our cache, decode it in to a JSON structure */
		json_error_t json_error;
		result = json_loads(json, 0, &json_error);
		if (result == NULL) {
			ox_error(r, "cached JSON was corrupted: %s", json_error.text);
			return FALSE;
		}
	}

	/* return the access_token JSON object */
	json_t *tkn = json_object_get(result, "access_token");
	if ((tkn != NULL) && (json_is_object(tkn))) {

		/*
		 * assume PingFederate validation: copy over those claims from the access_token
		 * that are relevant for authorization purposes
		 */
		json_object_set(tkn, "client_id", json_object_get(result, "client_id"));
		json_object_set(tkn, "scope", json_object_get(result, "scope"));

		//ox_oauth_spaced_string_to_array(r, result, "scope", tkn, "scopes");

		/* return only the pimped access_token results */
		*token = json_deep_copy(tkn);
		char *s_token = json_dumps(*token, 0);
		*response = apr_pstrdup(r->pool, s_token);
		free(s_token);

		json_decref(result);

	} else {

		//ox_oauth_spaced_string_to_array(r, result, "scope", result, "scopes");

		/* assume spec compliant introspection */
		*token = result;
		*response = apr_pstrdup(r->pool, json);

	}

	return TRUE;
}

/*
 * set the unique user identifier that will be propagated in the Apache r->user and REMOTE_USER variables
 */
static apr_byte_t ox_oauth_set_remote_user(request_rec *r, ox_cfg *c,
		json_t *token) {

	/* get the configured claim name to populate REMOTE_USER with (defaults to "Username") */
	char *claim_name = apr_pstrdup(r->pool, c->oauth.remote_user_claim.claim_name);

	/* get the claim value from the resolved token JSON response to use as the REMOTE_USER key */
	json_t *username = json_object_get(token, claim_name);
	if ((username == NULL) || (!json_is_string(username))) {
		ox_warn(r, "response JSON object did not contain a \"%s\" string",
				claim_name);
		return FALSE;
	}

	r->user = apr_pstrdup(r->pool, json_string_value(username));

	if (c->oauth.remote_user_claim.reg_exp != NULL) {

		char *error_str = NULL;
		if (ox_util_regexp_first_match(r->pool, r->user, c->oauth.remote_user_claim.reg_exp, &r->user, &error_str) == FALSE) {
			ox_error(r, "ox_util_regexp_first_match failed: %s", error_str);
			r->user = NULL;
			return FALSE;
		}
	}

	ox_debug(r, "set REMOTE_USER to claim %s=%s", claim_name,
			json_string_value(username));

	return TRUE;
}

/*
 * validate a JWT access token (locally)
 *
 * TODO: document that we're reusing the following settings from the OX config section:
 *       - JWKs URI refresh interval
 *       - encryption key material (OXPrivateKeyFiles)
 *       - iat slack (OXIDTokenIatSlack)
 *
 * OXOAuthRemoteUserClaim client_id
 * # 32x 61 hex
 * OXOAuthVerifySharedKeys aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 */
static apr_byte_t ox_oauth_validate_jwt_access_token(request_rec *r,
		ox_cfg *c, const char *access_token, json_t **token, char **response) {

	apr_jwt_error_t err;
	apr_jwt_t *jwt = NULL;
	if (apr_jwt_parse(r->pool, access_token, &jwt,
			ox_util_merge_symmetric_key(r->pool, c->private_keys,
					c->oauth.client_secret, NULL), &err) == FALSE) {
		ox_error(r, "could not parse JWT from access_token: %s",
				apr_jwt_e2s(r->pool, err));
		return FALSE;
	}

	/* validate the access token JWT, validating optional exp + iat */
	if (ox_proto_validate_jwt(r, jwt, NULL, FALSE, FALSE,
			c->provider.idtoken_iat_slack) == FALSE) {
		apr_jwt_destroy(jwt);
		return FALSE;
	}

	ox_debug(r,
			"verify JWT against %d statically configured public keys and %d shared keys, with JWKs URI set to %s",
			c->oauth.verify_public_keys ?
					apr_hash_count(c->oauth.verify_public_keys) : 0,
					c->oauth.verify_shared_keys ?
							apr_hash_count(c->oauth.verify_shared_keys) : 0,
							c->oauth.verify_jwks_uri);

	ox_jwks_uri_t jwks_uri = { c->oauth.verify_jwks_uri,
			c->provider.jwks_refresh_interval, c->oauth.ssl_validate_server };
	if (ox_proto_jwt_verify(r, c, jwt, &jwks_uri,
			ox_util_merge_key_sets(r->pool, c->oauth.verify_public_keys,
					c->oauth.verify_shared_keys)) == FALSE) {
		ox_error(r,
				"JWT access token signature could not be validated, aborting");
		apr_jwt_destroy(jwt);
		return FALSE;
	}

	ox_debug(r, "successfully verified JWT access token: %s",
			jwt->payload.value.str);

	*token = jwt->payload.value.json;
	*response = jwt->payload.value.str;

	return TRUE;
}

/*
 * main routine: handle OAuth 2.0 authentication/authorization
 */
int ox_oauth_check_userid(request_rec *r, ox_cfg *c) {

	/* check if this is a sub-request or an initial request */
	if (!ap_is_initial_req(r)) {

		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user = r->prev->user;

		if (r->user != NULL) {

			/* this is a sub-request and we have a session */
			ox_debug(r,
					"recycling user '%s' from initial request for sub-request",
					r->user);

			return OK;
		}
	}

	/* we don't have a session yet */

	/* get the bearer access token from the Authorization header */
	const char *access_token = NULL;
	if (ox_oauth_get_bearer_token(r, &access_token) == FALSE)
		return HTTP_UNAUTHORIZED;

	/* validate the obtained access token against the OAuth AS validation endpoint */
	json_t *token = NULL;
	char *s_token = NULL;

	/* check if an introspection endpoint is set */
	if (c->oauth.introspection_endpoint_url != NULL) {
		/* we'll validate the token remotely */
		if (ox_oauth_resolve_access_token(r, c, access_token, &token,
				&s_token) == FALSE)
			return HTTP_UNAUTHORIZED;
	} else {
		/* no introspection endpoint is set, assume the token is a JWT and validate it locally */
		if (ox_oauth_validate_jwt_access_token(r, c, access_token, &token,
				&s_token) == FALSE)
			return HTTP_UNAUTHORIZED;
	}

	/* check that we've got something back */
	if (token == NULL) {
		ox_error(r, "could not resolve claims (token == NULL)");
		return HTTP_UNAUTHORIZED;
	}

	/* store the parsed token (cq. the claims from the response) in the request state so it can be accessed by the authz routines */
	ox_request_state_set(r, OX_CLAIMS_SESSION_KEY, (const char *) s_token);

	/* set the REMOTE_USER variable */
	if (ox_oauth_set_remote_user(r, c, token) == FALSE) {
		ox_error(r,
				"remote user could not be set, aborting with HTTP_UNAUTHORIZED");
		return HTTP_UNAUTHORIZED;
	}

	/* get a handle to the director config */
	ox_dir_cfg *dir_cfg = (ox_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	/* set the user authentication HTTP header if set and required */
	if ((r->user != NULL) && (dir_cfg->authn_header != NULL)) {
		ox_debug(r, "setting authn header (%s) to: %s", dir_cfg->authn_header,
				r->user);
		apr_table_set(r->headers_in, dir_cfg->authn_header, r->user);
	}

	/* set the resolved claims in the HTTP headers for the target application */
	ox_util_set_app_headers(r, token, c->claim_prefix, c->claim_delimiter);

	/* set the access_token in the app headers */
	if (access_token != NULL) {
		ox_util_set_app_header(r, "access_token", access_token,
				OX_DEFAULT_HEADER_PREFIX);
	}

	/* free JSON resources */
	json_decref(token);

	return OK;
}
