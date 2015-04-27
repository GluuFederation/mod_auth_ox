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

#ifndef __OXD_MAIN_H_
#define __OXD_MAIN_H_

int ox_discovery(mod_ox_config *s_cfg);
int ox_check_id_token(mod_ox_config *s_cfg, const char *id_token, const char *session_id);
int ox_obtain_pat(mod_ox_config *s_cfg);
int ox_register_resources(mod_ox_config *s_cfg);
int ox_obtain_aat(mod_ox_config *s_cfg);
int ox_obtain_rpt(mod_ox_config *s_cfg);
int ox_register_ticket(mod_ox_config *s_cfg);
int ox_authorize_rpt(mod_ox_config *s_cfg, const char *session_id);
int ox_check_rpt_status(mod_ox_config *s_cfg);
int ox_get_id_token(mod_ox_config *s_cfg, const char *code, const char *redirect_uri, std::string& id_token, std::string& access_token, int *expire_in);

#endif
