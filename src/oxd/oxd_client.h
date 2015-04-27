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

#ifndef __OXD_CLIENT_H_
#define __OXD_CLIENT_H_

int oxd_discovery(const char *hostname, int portnum, const char *discovery_url, char *resp_str);
int oxd_register_client(const char *hostname, int portnum, const char *discovery_url, const char *redirect_url, const char *logout_redirect_url, const char *client_name, char *resp_str);
int oxd_obtain_pat(const char *hostname, int portnum, const char *discovery_url, const char *uma_discovery_url, const char *redirect_url, const char *client_id, const char *client_secret, const char *user_id, const char *user_secret, char *resp_str);
int oxd_obtain_aat(const char *hostname, int portnum, const char *discovery_url, const char *uma_discovery_url, const char *redirect_url, const char *client_id, const char *client_secret, const char *user_id, const char *user_secret, char *resp_str);
int oxd_obtain_rpt(const char *hostname, int portnum, const char *aat_token, const char *am_host, char *resp_str);
int oxd_check_rpt_status(const char *hostname, int portnum, const char *uma_discovery_url, const char *pat_token, const char *rpt_token, char *resp_str);
int oxd_check_rpt_token(const char *hostname, int portnum, const char *uma_discovery_url, const char *pat_token, const char *rpt_token, char *resp_str);
int oxd_register_ticket(const char *hostname, int portnum, const char *uma_discovery_url, const char *pat_token, const char *am_host, const char *rs_host,  const char *scopes, const char *resource_set_id, char *resp_str);
int oxd_register_resource(const char *hostname, int portnum, const char *uma_discovery_url, const char *pat_token, const char *resource_name,  const char *scopes, char *resp_str);
int oxd_authorize_rpt_token(const char *hostname, int portnum, const char *aat_token, const char *rpt_token, const char *am_host, const char *ticket, const char *claims, char *resp_str);
int oxd_check_id_token(const char *hostname, int portnum, const char *discovery_url, const char *id_token, char *resp_str);

#endif
