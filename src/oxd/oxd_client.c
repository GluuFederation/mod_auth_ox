/* Copyright (C) 2007-2011 Gluu (http://ox.gluu.org/doku.php?id=oxd:mod_ox)
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use,
* copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following
* conditions:
* 
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
* OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
* OTHER DEALINGS IN THE SOFTWARE.
* 
* Created by MalinImna <imna@gluu.org>
* 
*/

#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#include <apr_general.h>
#include <apr_network_io.h>
#include <apr_strings.h>

/* default socket timeout */
#define DEF_SOCK_TIMEOUT	(APR_USEC_PER_SEC * 60)

/* default buffer size */
#define BUFSIZE			8192

/**
* Connect to the remote host
*/
static apr_status_t do_connect(apr_socket_t **sock, apr_pool_t *mp, const char *hostname, apr_port_t portnum)
{
	apr_sockaddr_t *sa;
	apr_socket_t *s;
	apr_status_t rv;

	rv = apr_sockaddr_info_get(&sa, hostname, APR_INET, portnum, 0, mp);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	rv = apr_socket_create(&s, sa->family, SOCK_STREAM, APR_PROTO_TCP, mp);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	/* it is a good idea to specify socket options explicitly.
	* in this case, we make a blocking socket with timeout. */
	apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
	apr_socket_timeout_set(s, DEF_SOCK_TIMEOUT);

	rv = apr_socket_connect(s, sa);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	/* see the tutorial about the reason why we have to specify options again */
	apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
	apr_socket_timeout_set(s, DEF_SOCK_TIMEOUT);

	*sock = s;
	return APR_SUCCESS;
}

/**
* Send a request as a oxd protocol.
* Write the received response to the standard output until the EOF.
*/
static apr_status_t do_client_task(apr_socket_t *sock, const char *req_str, char *resp_str)
{
	apr_status_t rv;
	const char *req = req_str;
	char *resp = resp_str;
	apr_size_t len = strlen(req);
	rv = apr_socket_send(sock, req, &len);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	len = BUFSIZE;
	while (0) {
		rv = apr_socket_recv(sock, resp, &len);
		if (len > 0) {
			break;
		}
	}
	rv = apr_socket_recv(sock, resp, &len);

	return rv;
}

int oxd_discovery(const char *hostname, int portnum, const char *discovery_url, char *resp_str)
{
    apr_status_t rv;
    apr_pool_t *mp;
    apr_socket_t *s;
	char req[BUFSIZE]="";
 
    if ((discovery_url == NULL) || (hostname == NULL) || (portnum < 0)) {
        return -1;
    }
    
    apr_initialize();
    apr_pool_create(&mp, NULL);

    rv = do_connect(&s, mp, hostname, portnum);
    if (rv != APR_SUCCESS) {
        goto error;
    }
    
	strcat(req, "    ");
	strcat(req, "{\"command\":\"discovery\",\"params\":{\"discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, discovery_url);
	strcat(req, "/.well-known/openid-configuration");
	strcat(req, "\"}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

    rv = do_client_task(s, req, resp_str);
    if (rv != APR_SUCCESS) {
        goto error;
    }
    apr_socket_close(s);
    
    apr_terminate();
    return 0;

 error:
    apr_terminate();
    return -1;
}

int oxd_register_client(const char *hostname, int portnum, \
				  const char *discovery_url, const char *redirect_url, const char *logout_redirect_url, \
				  const char *client_name, char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if ((discovery_url == NULL) || 
		(redirect_url == NULL) || 
		(logout_redirect_url == NULL) || 
		(client_name == NULL) || 
		(hostname == NULL) || 
		(portnum < 0)) {
		return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"register_client\",\"params\":{\"discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, discovery_url);
	strcat(req, "/.well-known/openid-configuration");
	strcat(req, "\",\"redirect_url\":\"");
	strcat(req, redirect_url);
	strcat(req, "\",\"logout_redirect_url\":\"");
	strcat(req, logout_redirect_url);
	strcat(req, "\",\"client_name\":\"");
	strcat(req, client_name);
	strcat(req, "\"}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_obtain_pat(const char *hostname, int portnum, \
				 const char *discovery_url, const char *uma_discovery_url, const char *redirect_url, \
				 const char *client_id, const char *client_secret, \
				 const char *user_id, const char *user_secret, \
				 char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if (!discovery_url || !uma_discovery_url || !redirect_url || !client_id || !client_secret || !user_id || !user_secret || !hostname || 
		(portnum < 0)) {
			return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"obtain_pat\",\"params\":{\"discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, discovery_url);
	strcat(req, "/.well-known/openid-configuration");
	strcat(req, "\",\"uma_discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, uma_discovery_url);
	strcat(req, "/.well-known/uma-configuration");
	strcat(req, "\",\"redirect_url\":\"");
	strcat(req, redirect_url);
	strcat(req, "\",\"client_id\":\"");
	strcat(req, client_id);
	strcat(req, "\",\"client_secret\":\"");
	strcat(req, client_secret);
	strcat(req, "\",\"user_id\":\"");
	strcat(req, user_id);
	strcat(req, "\",\"user_secret\":\"");
	strcat(req, user_secret);
	strcat(req, "\"}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_register_resource(const char *hostname, int portnum, const char *uma_discovery_url, const char *pat_token, \
				   const char *resource_name, const char *scopes, char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if (!uma_discovery_url || !pat_token || !resource_name || !hostname || !scopes || (portnum < 0)) {
			return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"register_resource\",\"params\":{\"uma_discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, uma_discovery_url);
	strcat(req, "/.well-known/uma-configuration");
	strcat(req, "\",\"pat\":\"");
	strcat(req, pat_token);
	strcat(req, "\",\"name\":\"");
	strcat(req, resource_name);
	strcat(req, "\",\"scopes\":[");
	strcat(req, scopes);
	strcat(req, "]");
	strcat(req, "}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_obtain_aat(const char *hostname, int portnum, \
				   const char *discovery_url, const char *uma_discovery_url, const char *redirect_url, \
				   const char *client_id, const char *client_secret, \
				   const char *user_id, const char *user_secret, \
				   char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if (!discovery_url || !uma_discovery_url || !redirect_url || !client_id || !client_secret || !user_id || !user_secret || !hostname || 
		(portnum < 0)) {
			return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"obtain_aat\",\"params\":{\"discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, discovery_url);
	strcat(req, "/.well-known/openid-configuration");
	strcat(req, "\",\"uma_discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, uma_discovery_url);
	strcat(req, "/.well-known/uma-configuration");
	strcat(req, "\",\"redirect_url\":\"");
	strcat(req, redirect_url);
	strcat(req, "\",\"client_id\":\"");
	strcat(req, client_id);
	strcat(req, "\",\"client_secret\":\"");
	strcat(req, client_secret);
	strcat(req, "\",\"user_id\":\"");
	strcat(req, user_id);
	strcat(req, "\",\"user_secret\":\"");
	strcat(req, user_secret);
	strcat(req, "\"}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_obtain_rpt(const char *hostname, int portnum, const char *aat_token, const char *am_host, char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if (!aat_token || !hostname || (portnum < 0)) {
			return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"obtain_rpt\",\"params\":{\"aat_token\":\"");
	strcat(req, aat_token);
	strcat(req, "\",\"am_host\":\"");
	strcat(req, am_host);
	strcat(req, "\"}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_check_rpt_status(const char *hostname, int portnum, const char *uma_discovery_url, const char *pat_token, const char *rpt_token, char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if (!uma_discovery_url || !pat_token || !rpt_token || !hostname || (portnum < 0)) {
		return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"rpt_status\",\"params\":{\"uma_discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, uma_discovery_url);
	strcat(req, "/.well-known/uma-configuration");
	strcat(req, "\",\"pat\":\"");
	strcat(req, pat_token);
	strcat(req, "\",\"rpt\":\"");
	strcat(req, rpt_token);
	strcat(req, "\"}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_register_ticket(const char *hostname, int portnum, const char *uma_discovery_url, \
						const char *pat_token, const char *am_host, const char *rs_host, \
						const char *scopes, const char *resource_set_id, char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if (!uma_discovery_url || !pat_token || !am_host || !rs_host || !resource_set_id || !hostname  || !scopes || (portnum < 0)) {
		return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"register_ticket\",\"params\":{\"uma_discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, uma_discovery_url);
	strcat(req, "/.well-known/uma-configuration");
	strcat(req, "\",\"pat\":\"");
	strcat(req, pat_token);
	strcat(req, "\",\"am_host\":\"");
	strcat(req, am_host);
	strcat(req, "\",\"rs_host\":\"");
	strcat(req, rs_host);
	strcat(req, "\",\"resource_set_id\":\"");
	strcat(req, resource_set_id);

	strcat(req, "\",\"scopes\":[");
	strcat(req, scopes);
	strcat(req, "]");

	strcat(req, "}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_authorize_rpt_token(const char *hostname, int portnum, const char *aat_token, \
							const char *rpt_token, const char *am_host, const char *ticket, \
							const char *claims, char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if ((aat_token == NULL) || 
		(rpt_token == NULL) || 
		(am_host == NULL) || 
		(ticket == NULL) || 
		(hostname == NULL) || 
		(portnum < 0)) {
			return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"authorize_rpt\",\"params\":{\"aat_token\":\"");
	strcat(req, aat_token);
	strcat(req, "\",\"rpt_token\":\"");
	strcat(req, rpt_token);
	strcat(req, "\",\"am_host\":\"");
	strcat(req, am_host);
	strcat(req, "\",\"ticket\":\"");
	strcat(req, ticket);
	strcat(req, "\",\"claims\":");
	strcat(req, "{");
	if (claims != NULL)
		strcat(req, claims);
	strcat(req, "}");
	strcat(req, "}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	apr_terminate();
	return 0;

error:
	apr_terminate();
	return -1;
}

int oxd_check_id_token(const char *hostname, int portnum, const char *discovery_url, const char *id_token, char *resp_str)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;
	char req[BUFSIZE]="";

	if ((discovery_url == NULL) || 
		(id_token == NULL) || 
		(hostname == NULL) || 
		(portnum < 0)) {
			return -1;
	}

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = do_connect(&s, mp, hostname, portnum);
	if (rv != APR_SUCCESS) {
		goto error;
	}

	strcat(req, "    ");
	strcat(&req[4], "{\"command\":\"id_token_status\",\"params\":{\"discovery_url\":\"");
	strcat(req, "https://");
	strcat(req, discovery_url);
	strcat(req, "/.well-known/openid-configuration");
	strcat(req, "\",\"id_token\":\"");
	strcat(req, id_token);
	strcat(req, "\"}}");
	sprintf(&req[0], "%04lu", strlen(req)-4);
	req[4] = '{';

	rv = do_client_task(s, req, resp_str);
	if (rv != APR_SUCCESS) {
		goto error;
	}
	apr_socket_close(s);

	/* destroy the memory pool. These chunks above are freed by this */
	apr_pool_destroy(mp);

	apr_terminate();
	return 0;

error:
	/* destroy the memory pool. These chunks above are freed by this */
	apr_pool_destroy(mp);

	apr_terminate();
	return -1;
}
