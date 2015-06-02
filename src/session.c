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

#include <apr_base64.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>

#include "mod_auth_ox.h"

#ifdef WIN32
extern "C" module AP_MODULE_DECLARE_DATA auth_ox_module;
#else
extern module AP_MODULE_DECLARE_DATA auth_ox_module;
#endif

/* the name of the remote-user attribute in the session  */
#define OX_SESSION_REMOTE_USER_KEY "remote-user"
/* the name of the session expiry attribute in the session */
#define OX_SESSION_EXPIRY_KEY      "ox-expiry"
/* the name of the uuid attribute in the session */
#define OX_SESSION_UUID_KEY        "ox-uuid"

static apr_status_t (*ap_session_load_fn)(request_rec *r, session_rec **z) =
		NULL;
static apr_status_t (*ap_session_get_fn)(request_rec *r, session_rec *z,
		const char *key, const char **value) = NULL;
static apr_status_t (*ap_session_set_fn)(request_rec *r, session_rec *z,
		const char *key, const char *value) = NULL;
static apr_status_t (*ap_session_save_fn)(request_rec *r, session_rec *z) = NULL;

apr_status_t ox_session_load(request_rec *r, session_rec **zz) {
	apr_status_t rc = ap_session_load_fn(r, zz);
	(*zz)->remote_user = apr_table_get((*zz)->entries,
			OX_SESSION_REMOTE_USER_KEY);
	const char *uuid = apr_table_get((*zz)->entries, OX_SESSION_UUID_KEY);
	ox_debug(r, "%s", uuid ? uuid : "<null>");
	if (uuid != NULL)
		apr_uuid_parse((*zz)->uuid, uuid);
	return rc;
}

apr_status_t ox_session_save(request_rec *r, session_rec *z) {
	ox_session_set(r, z, OX_SESSION_REMOTE_USER_KEY, z->remote_user);
	char key[APR_UUID_FORMATTED_LENGTH + 1];
	apr_uuid_format((char *) &key, z->uuid);
	ox_debug(r, "%s", key);
	ox_session_set(r, z, OX_SESSION_UUID_KEY, key);
	return ap_session_save_fn(r, z);
}

apr_status_t ox_session_get(request_rec *r, session_rec *z, const char *key,
		const char **value) {
	return ap_session_get_fn(r, z, key, value);
}

apr_status_t ox_session_set(request_rec *r, session_rec *z, const char *key,
		const char *value) {
	return ap_session_set_fn(r, z, key, value);
}

apr_status_t ox_session_kill(request_rec *r, session_rec *z) {
	apr_table_clear(z->entries);
	z->expiry = 0;
	z->encoded = NULL;
	return ap_session_save_fn(r, z);
}

#ifndef OX_SESSION_USE_APACHE_SESSIONS

// compatibility stuff copied from:
// http://contribsoft.caixamagica.pt/browser/internals/2012/apachecc/trunk/mod_session-port/src/util_port_compat.c
#define T_ESCAPE_URLENCODED    (64)

static const unsigned char test_c_table[256] = { 32, 126, 126, 126, 126, 126,
		126, 126, 126, 126, 127, 126, 126, 126, 126, 126, 126, 126, 126, 126,
		126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 14, 64, 95,
		70, 65, 102, 65, 65, 73, 73, 1, 64, 72, 0, 0, 74, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 104, 79, 79, 72, 79, 79, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79, 95, 79, 71, 0, 71, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 79, 103, 79, 65, 126, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
		118, 118, 118, 118, 118, 118, 118 };

#define TEST_CHAR(c, f)        (test_c_table[(unsigned)(c)] & (f))

static const char c2x_table[] = "0123456789abcdef";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
		unsigned char *where) {
#if APR_CHARSET_EBCDIC
	what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
	*where++ = prefix;
	*where++ = c2x_table[what >> 4];
	*where++ = c2x_table[what & 0xf];
	return where;
}

static char x2c(const char *what) {
	register char digit;

#if !APR_CHARSET_EBCDIC
	digit =
			((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
	digit *= 16;
	digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
	char xstr[5];
	xstr[0]='0';
	xstr[1]='x';
	xstr[2]=what[0];
	xstr[3]=what[1];
	xstr[4]='\0';
	digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
			0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
	return (digit);
}

#ifndef WIN32
AP_DECLARE(char *) ap_escape_urlencoded_buffer(char *copy, const char *buffer) {
	const unsigned char *s = (const unsigned char *) buffer;
	unsigned char *d = (unsigned char *) copy;
	unsigned c;

	while ((c = *s)) {
		if (TEST_CHAR(c, T_ESCAPE_URLENCODED)) {
			d = c2x(c, '%', d);
		} else if (c == ' ') {
			*d++ = '+';
		} else {
			*d++ = c;
		}
		++s;
	}
	*d = '\0';
	return copy;
}
#endif

static int ox_session_unescape_url(char *url, const char *forbid,
		const char *reserved) {
	register int badesc, badpath;
	char *x, *y;

	badesc = 0;
	badpath = 0;
	/* Initial scan for first '%'. Don't bother writing values before
	 * seeing a '%' */
	y = strchr(url, '%');
	if (y == NULL) {
		return OK;
	}
	for (x = y; *y; ++x, ++y) {
		if (*y != '%') {
			*x = *y;
		} else {
			if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
				badesc = 1;
				*x = '%';
			} else {
				char decoded;
				decoded = x2c(y + 1);
				if ((decoded == '\0')
						|| (forbid && ap_strchr_c(forbid, decoded))) {
					badpath = 1;
					*x = decoded;
					y += 2;
				} else if (reserved && ap_strchr_c(reserved, decoded)) {
					*x++ = *y++;
					*x++ = *y++;
					*x = *y;
				} else {
					*x = decoded;
					y += 2;
				}
			}
		}
	}
	*x = '\0';
	if (badesc) {
		return HTTP_BAD_REQUEST;
	} else if (badpath) {
		return HTTP_NOT_FOUND;
	} else {
		return OK;
	}
}

#ifndef WIN32
AP_DECLARE(int) ap_unescape_urlencoded(char *query) {
	char *slider;
	/* replace plus with a space */
	if (query) {
		for (slider = query; *slider; slider++) {
			if (*slider == '+') {
				*slider = ' ';
			}
		}
	}
	/* unescape everything else */
	return ox_session_unescape_url(query, NULL, NULL);
}
#endif

// copied from mod_session.c
static apr_status_t ox_session_identity_decode(request_rec * r,
		session_rec * z) {
	char *last = NULL;
	char *encoded, *pair;
	const char *sep = "&";

	//ox_debug(r, "decoding %s", z->encoded);

	/* sanity check - anything to decode? */
	if (!z->encoded) {
		return APR_SUCCESS;
	}

	/* decode what we have */
	encoded = apr_pstrdup(r->pool, z->encoded);
	pair = apr_strtok(encoded, sep, &last);
	while (pair && pair[0]) {
		char *plast = NULL;
		const char *psep = "=";
		char *key = apr_strtok(pair, psep, &plast);
		char *val = apr_strtok(NULL, psep, &plast);

		//ox_debug(r, "decoding %s=%s", key, val);

		if (key && *key) {
			if (!val || !*val) {
				apr_table_unset(z->entries, key);
			} else if (!ap_unescape_urlencoded(key)
					&& !ap_unescape_urlencoded(val)) {
				if (!strcmp(OX_SESSION_EXPIRY_KEY, key)) {
					z->expiry = (apr_time_t) apr_atoi64(val);
				} else {
					apr_table_set(z->entries, key, val);
				}
			}
		}
		pair = apr_strtok(NULL, sep, &last);
	}
	z->encoded = NULL;
	return APR_SUCCESS;
}

// copied from mod_session.c
static int ox_identity_count(int *count, const char *key, const char *val) {
	*count += (int)strlen(key) * 3 + (int)strlen(val) * 3 + 1;
	return 1;
}

// copied from mod_session.c
static int ox_identity_concat(char *buffer, const char *key, const char *val) {
	char *slider = buffer;
	int length = (int)strlen(slider);
	slider += length;
	if (length) {
		*slider = '&';
		slider++;
	}
	ap_escape_urlencoded_buffer(slider, key);
	slider += strlen(slider);
	*slider = '=';
	slider++;
	ap_escape_urlencoded_buffer(slider, val);
	return 1;
}

// copied from mod_session.c
static apr_status_t ox_session_identity_encode(request_rec * r,
		session_rec * z) {
	char *buffer = NULL;
	int length = 0;
	if (z->expiry) {
		char *expiry = apr_psprintf(z->pool, "%" APR_INT64_T_FMT, z->expiry);
		apr_table_setn(z->entries, OX_SESSION_EXPIRY_KEY, expiry);
	}
	apr_table_do(
			(int (*)(void *, const char *, const char *)) ox_identity_count,
			&length, z->entries, NULL);
	buffer = (char *)apr_pcalloc(r->pool, length + 1);
	apr_table_do(
			(int (*)(void *, const char *, const char *)) ox_identity_concat,
			buffer, z->entries, NULL);
	z->encoded = buffer;
	return APR_SUCCESS;

}

/* load the session from the cache using the cookie as the index */
static apr_status_t ox_session_load_cache(request_rec *r, session_rec *z) {
	ox_cfg *c = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);
	ox_dir_cfg *d = (ox_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	/* get the cookie that should be our uuid/key */
	char *uuid = ox_util_get_cookie(r, d->cookie);

	/* get the string-encoded session from the cache based on the key */
	if (uuid != NULL) {
		c->cache->get(r, OX_CACHE_SECTION_SESSION, uuid, &z->encoded);
		//ox_util_set_cookie(r, d->cookie, "");
	}

	return (z->encoded != NULL) ? APR_SUCCESS : APR_EGENERAL;
}

/*
 * save the session to the cache using a cookie for the index
 */
static apr_status_t ox_session_save_cache(request_rec *r, session_rec *z) {
	ox_cfg *c = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);
	ox_dir_cfg *d = (ox_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	char key[APR_UUID_FORMATTED_LENGTH + 1];
	apr_uuid_format((char *) &key, z->uuid);

	if (z->encoded && z->encoded[0]) {

		/* set the uuid in the cookie */
		ox_util_set_cookie(r, d->cookie, key, -1);

		/* store the string-encoded session in the cache */
		c->cache->set(r, OX_CACHE_SECTION_SESSION, key, z->encoded,
				z->expiry);

	} else {

		/* clear the cookie */
		ox_util_set_cookie(r, d->cookie, "", 0);

		/* remove the session from the cache */
		c->cache->set(r, OX_CACHE_SECTION_SESSION, key, NULL, 0);
	}

	return APR_SUCCESS;
}

static apr_status_t uma_session_save_cache(request_rec *r, session_rec *z) {
	uma_cfg *c = (uma_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);
	uma_dir_cfg *d = (uma_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	char key[APR_UUID_FORMATTED_LENGTH + 1];
	apr_uuid_format((char *) &key, z->uuid);

	if (z->encoded && z->encoded[0]) {

		/* set the uuid in the cookie */
		ox_util_set_cookie(r, d->cookie, key, -1);

		/* store the string-encoded session in the cache */
		c->cache->set(r, UMA_CACHE_SECTION_SESSION, key, z->encoded,
				z->expiry);

	} else {

		/* clear the cookie */
		ox_util_set_cookie(r, d->cookie, "", 0);

		/* remove the session from the cache */
		c->cache->set(r, UMA_CACHE_SECTION_SESSION, key, NULL, 0);
	}

	return APR_SUCCESS;
}

static apr_status_t ox_session_load_cookie(request_rec *r, session_rec *z) {
	ox_dir_cfg *d = (ox_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	char *cookieValue = ox_util_get_cookie(r, d->cookie);
	if (cookieValue != NULL) {
		if (ox_base64url_decode_decrypt_string(r, (char **) &z->encoded,
				cookieValue) <= 0) {
			//ox_util_set_cookie(r, d->cookie, "");
			ox_warn(r, "cookie value possibly corrupted");
			return APR_EGENERAL;
		}
	}

	return APR_SUCCESS;
}

static apr_status_t uma_session_load_cookie(request_rec *r, session_rec *z) {
	uma_dir_cfg *d = (uma_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	char *cookieValue = ox_util_get_cookie(r, d->cookie);
	if (cookieValue != NULL) {
		if (ox_base64url_decode_decrypt_string(r, (char **) &z->encoded,
				cookieValue) <= 0) {
			//ox_util_set_cookie(r, d->cookie, "");
			ox_warn(r, "cookie value possibly corrupted");
			return APR_EGENERAL;
		}
	}

	return APR_SUCCESS;
}

static apr_status_t ox_session_save_cookie(request_rec *r, session_rec *z) {
	ox_dir_cfg *d = (ox_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	char *cookieValue = "";
	if (z->encoded && z->encoded[0]) {
		ox_encrypt_base64url_encode_string(r, &cookieValue, z->encoded);
	}
	ox_util_set_cookie(r, d->cookie, cookieValue, -1);

	return APR_SUCCESS;
}

static apr_status_t uma_session_save_cookie(request_rec *r, session_rec *z) {
	uma_dir_cfg *d = (uma_dir_cfg *)ap_get_module_config(r->per_dir_config,
			&auth_ox_module);

	char *cookieValue = "";
	if (z->encoded && z->encoded[0]) {
		ox_encrypt_base64url_encode_string(r, &cookieValue, z->encoded);
	}
	ox_util_set_cookie(r, d->cookie, cookieValue, -1);

	return APR_SUCCESS;
}

/*
 * load the session from the request context, create a new one if no luck
 */
static apr_status_t ox_session_load_22(request_rec *r, session_rec **zz) {

	ox_cfg *c = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);

	/* first see if this is a sub-request and it was set already in the main request */
	if (((*zz) = (session_rec *) ox_request_state_get(r, "session")) != NULL) {
		ox_debug(r, "loading session from request state");
		return APR_SUCCESS;
	}

	/* allocate space for the session object and fill it */
	session_rec *z = (*zz = (session_rec *)apr_pcalloc(r->pool, sizeof(session_rec)));
	z->pool = r->pool;

	/* get a new uuid for this session */
	z->uuid = (apr_uuid_t *) apr_pcalloc(z->pool, sizeof(apr_uuid_t));
	apr_uuid_get(z->uuid);

	z->remote_user = NULL;
	z->encoded = NULL;
	z->entries = apr_table_make(z->pool, 10);

	apr_status_t rc = APR_SUCCESS;
	if (c->session_type == OX_SESSION_TYPE_22_SERVER_CACHE) {
		/* load the session from the cache */
		rc = ox_session_load_cache(r, z);
	} else if (c->session_type == OX_SESSION_TYPE_22_CLIENT_COOKIE) {
		/* load the session from a self-contained cookie */
		rc = ox_session_load_cookie(r, z);
	} else {
		ox_error(r, "ox_session_load_22: unknown session type: %d",
				c->session_type);
		rc = APR_EGENERAL;
	}

	/* see if it worked out */
	if (rc != APR_SUCCESS)
		return rc;

	/* yup, now decode the info */
	if (ox_session_identity_decode(r, z) != APR_SUCCESS)
		return APR_EGENERAL;

	/* check whether it has expired */
	if (apr_time_now() > z->expiry) {

		ox_warn(r, "session restored from cache has expired");
		apr_table_clear(z->entries);
		z->expiry = 0;
		z->encoded = NULL;

		return APR_EGENERAL;
	}

	/* store this session in the request context, so it is available to sub-requests */
	ox_request_state_set(r, "session", (const char *) z);

	return APR_SUCCESS;
}

static apr_status_t uma_session_load_22(request_rec *r, session_rec **zz) {

	ox_cfg *c = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);

	/* first see if this is a sub-request and it was set already in the main request */
	if (((*zz) = (session_rec *) uma_request_state_get(r, "session")) != NULL) {
		ox_debug(r, "loading session from request state");
		return APR_SUCCESS;
	}

	/* allocate space for the session object and fill it */
	session_rec *z = (*zz = (session_rec *)apr_pcalloc(r->pool, sizeof(session_rec)));
	z->pool = r->pool;

	/* get a new uuid for this session */
	z->remote_user = NULL;
	z->encoded = NULL;
	z->entries = apr_table_make(z->pool, 10);

	apr_status_t rc = APR_SUCCESS;
	if (c->session_type == OX_SESSION_TYPE_22_SERVER_CACHE) {
		/* load the session from the cache */
		rc = uma_session_load_cache(r, z);
	} else if (c->session_type == OX_SESSION_TYPE_22_CLIENT_COOKIE) {
		/* load the session from a self-contained cookie */
		rc = ox_session_load_cookie(r, z);
	} else {
		ox_error(r, "ox_session_load_22: unknown session type: %d",
				c->session_type);
		rc = APR_EGENERAL;
	}

	/* see if it worked out */
	if (rc != APR_SUCCESS)
		return rc;

	/* yup, now decode the info */
	if (ox_session_identity_decode(r, z) != APR_SUCCESS)
		return APR_EGENERAL;

	/* check whether it has expired */
	if (apr_time_now() > z->expiry) {

		ox_warn(r, "session restored from cache has expired");
		apr_table_clear(z->entries);
		z->expiry = 0;
		z->encoded = NULL;

		return APR_EGENERAL;
	}

	/* store this session in the request context, so it is available to sub-requests */
	ox_request_state_set(r, "session", (const char *) z);

	return APR_SUCCESS;
}

/*
 * save a session to the cache
 */
static apr_status_t ox_session_save_22(request_rec *r, session_rec *z) {

	ox_cfg *c = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);

	/* encode the actual state in to the encoded string */
	ox_session_identity_encode(r, z);

	/* store this session in the request context, so it is available to sub-requests as a quicker-than-file-backend cache */
	ox_request_state_set(r, "session", (const char *) z);

	apr_status_t rc = APR_SUCCESS;
	if (c->session_type == OX_SESSION_TYPE_22_SERVER_CACHE) {
		/* store the session in the cache */
		rc = ox_session_save_cache(r, z);
	} else if (c->session_type == OX_SESSION_TYPE_22_CLIENT_COOKIE) {
		/* store the session in a self-contained cookie */
		rc = ox_session_save_cookie(r, z);
	} else {
		ox_error(r, "unknown session type: %d", c->session_type);
		rc = APR_EGENERAL;
	}

	return rc;
}

static apr_status_t uma_session_save_22(request_rec *r, session_rec *z) {

	ox_cfg *c = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);

	/* encode the actual state in to the encoded string */
	uma_session_identity_encode(r, z);

	/* store this session in the request context, so it is available to sub-requests as a quicker-than-file-backend cache */
	ox_request_state_set(r, "session", (const char *) z);

	apr_status_t rc = APR_SUCCESS;
	if (c->session_type == OX_SESSION_TYPE_22_SERVER_CACHE) {
		/* store the session in the cache */
		rc = uma_session_save_cache(r, z);
	} else if (c->session_type == OX_SESSION_TYPE_22_CLIENT_COOKIE) {
		/* store the session in a self-contained cookie */
		rc = ox_session_save_cookie(r, z);
	} else {
		ox_error(r, "unknown session type: %d", c->session_type);
		rc = APR_EGENERAL;
	}

	if (r->herders_out)
	{
		rc = uma_session_store_cache(r, z);
	}

	return rc;
}

/*
 * get a value from the session based on the name from a name/value pair
 */
static apr_status_t ox_session_get_22(request_rec *r, session_rec *z,
		const char *key, const char **value) {

	/* just return the value for the key */
	*value = apr_table_get(z->entries, key);

	return OK;
}

static apr_status_t uma_session_get_22(request_rec *r, session_rec *z,
		const char *key, const char **value) {

	/* just return the value for the key */
	*value = apr_table_get(z->entries, key);

	return OK;
}

/*
 * set a name/value key pair in the session
 */
static apr_status_t ox_session_set_22(request_rec *r, session_rec *z,
		const char *key, const char *value) {

	/* only set it if non-NULL, otherwise delete the entry */
	if (value) {
		apr_table_set(z->entries, key, value);
	} else {
		apr_table_unset(z->entries, key);
	}
	return OK;
}

static apr_status_t uma_session_set_22(request_rec *r, session_rec *z,
		const char *key, const char *value) {

	/* only set it if non-NULL, otherwise delete the entry */
	if (value) {
		apr_table_set(z->entries, key, value);
	} else {
		apr_table_unset(z->entries, key);
	}
	return OK;
}

/*
 * session initialization for pre-2.4
 */
apr_status_t ox_session_init() {
	if (!ap_session_load_fn || !ap_session_get_fn || !ap_session_set_fn
			|| !ap_session_save_fn) {
		ap_session_load_fn = ox_session_load_22;
		ap_session_get_fn = ox_session_get_22;
		ap_session_set_fn = ox_session_set_22;
		ap_session_save_fn = ox_session_save_22;
	}
	return OK;
}

apr_status_t uma_session_init() {
	if (!ap_session_load_fn || !ap_session_get_fn || !ap_session_set_fn
			|| !ap_session_save_fn) {
		ap_session_load_fn = uma_session_load_22;
		ap_session_get_fn = uma_session_get_22;
		ap_session_set_fn = uma_session_set_22;
		ap_session_save_fn = uma_session_save_22;
	}
	return OK;
}

#else

/*
 * use Apache 2.4 session handling
 */

#include <apr_optional.h>

apr_status_t ox_session_init() {
	if (!ap_session_load_fn || !ap_session_get_fn || !ap_session_set_fn || !ap_session_save_fn) {
		ap_session_load_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
		ap_session_get_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
		ap_session_set_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);
		ap_session_save_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_save);
	}
	return OK;
}

#endif
