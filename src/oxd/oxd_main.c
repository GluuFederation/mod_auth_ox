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

#include "oxd_client.h"
#include "oxd_main.h"

#include "curl/curl.h"

//////////////////////////////////////////////////////////////////////////
///  Group of functions for oxd communication 
/*
* Discovery and Register Client with oxd
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#discovery
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#register_client
*/
int ox_discovery(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	char deserializeStr[BUF_SIZE];
	double keyIntValue;
	int ret;
	int responseLen;
	char tmp[5];

	ret = oxd_discovery(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, s_cfg->OpenIDProvider, responseStr);
	if (ret == RET_FAILURE)
		goto OX_DISCOVERY_FAILED;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				goto OX_DISCOVERY_FAILED;
		}

		if (libjson_getKeyValue("data.issuer", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.issuer", keyValue, 0);
		}

		if (libjson_getKeyValue("data.authorization_endpoint", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.authorization_endpoint", keyValue, 0);
		}

		if (libjson_getKeyValue("data.token_endpoint", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.token_endpoint", keyValue, 0);
		}
	}
	else
	{
		goto OX_DISCOVERY_FAILED;
	}

	if (s_cfg->ApplicationPostLogoutRedirectUrl)
		ret = oxd_register_client(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, s_cfg->OpenIDProvider, s_cfg->OpenIDClientRedirectURIs, s_cfg->ApplicationPostLogoutRedirectUrl, s_cfg->OpenIDClientName, responseStr);
	else
		ret = oxd_register_client(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, s_cfg->OpenIDProvider, s_cfg->OpenIDClientRedirectURIs, "", s_cfg->OpenIDClientName, responseStr);
	
	if (ret == RET_FAILURE)
		goto OX_DISCOVERY_FAILED;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				goto OX_DISCOVERY_FAILED;
		}
		else
		{
			goto OX_DISCOVERY_FAILED;
		}

		keyIntValue = 0;
		int timeout;
		if (libjson_getKeyValue("data.client_secret_expires_at", &keyIntValue) == RET_SUCCESS)
		{
			time_t rawtime;
			time (&rawtime);
			if (rawtime < (time_t)keyIntValue)
				timeout = (int)((time_t)keyIntValue-rawtime);
			else
				timeout = 0;
		}
		else
		{
			goto OX_DISCOVERY_FAILED;
		}

		if (libjson_getKeyValue("data.client_id", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id", keyValue, timeout);
		else
			goto OX_DISCOVERY_FAILED;

		if (libjson_getKeyValue("data.client_secret", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret", keyValue, timeout);
		else
			goto OX_DISCOVERY_FAILED;

		if (libjson_getKeyValue("data.registration_access_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "oxd.registration_access_token", keyValue, timeout);
		else
			goto OX_DISCOVERY_FAILED;
	}
	else
	{
		goto OX_DISCOVERY_FAILED;
	}

	// Save Client info into filesystem
	if (s_cfg->ClientCredsPath)
	{
		if (libjson_deserialize(&responseStr[4], responseLen, deserializeStr, BUF_SIZE) != -1)
		{
			FILE *fp;
			fp = fopen(s_cfg->ClientCredsPath, "w");
			if (fp != NULL)
			{
				fwrite(deserializeStr, 1, strlen(deserializeStr), fp);
				fclose(fp);
			}
		}
	}
	
	return 0;

OX_DISCOVERY_FAILED:
	Remove_Ox_Storage(s_cfg->OpenIDClientName, "oxd.issuer");
	Remove_Ox_Storage(s_cfg->OpenIDClientName, "oxd.authorization_endpoint");
	Remove_Ox_Storage(s_cfg->OpenIDClientName, "oxd.token_endpoint");
	Remove_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
	Remove_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret");
	Remove_Ox_Storage(s_cfg->OpenIDClientName, "oxd.registration_access_token");
	return -1;
}

/*
* Check status of ID Token
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#check_status_of_id_token
*/
int ox_check_id_token(mod_ox_config *s_cfg, const char *id_token, const char *session_id)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	double keyIntValue;
	char tmp[5];
	int timeout;

	if (id_token==NULL)
		return -1;

	ret = oxd_check_id_token(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, s_cfg->OpenIDProvider, id_token, responseStr);
	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4);
	tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
			return -1;
		
		bool keyBoolValue=false;
		if (libjson_getKeyValue("data.active", &keyBoolValue) == RET_SUCCESS)
		{
//			if (keyBoolValue != true)
//				return -1;
		}
		else
			return -1;
/*
		// Check auth mode
		if (libjson_getKeyValue("data.claims.amr[0]", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (s_cfg->OpenIDRequestedACR)
			{
				if (strcmp(keyValue, s_cfg->OpenIDRequestedACR))
					return -1;
			}
		}
		else
			return -1;
*/

		// Set timeout
		keyIntValue = 0;
		if (libjson_getKeyValue("data.expires_at", &keyIntValue) == RET_SUCCESS)
		{
			time_t rawtime;
			time (&rawtime);
			if (rawtime < (time_t)keyIntValue)
				timeout = (int)((time_t)keyIntValue-rawtime);
			else
				timeout = 0;

			if (timeout <= 0)
				return -1;

		}
		else
		{
			return -1;
		}

		// Check Client ID
		if (libjson_getKeyValue("data.claims.aud[0]", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
			if (!client_id)	return -1;

			if (strcmp(keyValue, client_id))
			{
				free(client_id);
				return -1;
			}
			free(client_id);
		}
		else
			return -1;

		// Get User Claims
		char *token[MAX_ATTR_NUM];
		char uma_claims_str[1024];
		int i = 0;
		std::string attr_name;

		for (i=0; i<MAX_ATTR_NUM; i++)
			token[i] = NULL;

		strcpy(uma_claims_str, s_cfg->uma_sent_user_claims);
		i = 0;
		token[i] = strtok(uma_claims_str, "+");
		while(token[i]!= NULL) 
		{
			i++; if (i >= MAX_ATTR_NUM) break;		
			token[i] = strtok(NULL, "+");
		}

		i = 0;
		while(token[i]!= NULL) 
		{
			attr_name = "data";
			attr_name += ".";
			attr_name += "claims";
			attr_name += ".";
			attr_name += token[i];
			attr_name += "[0]";

			if (libjson_getKeyValue((char *)attr_name.c_str(), keyValue, BUF_SIZE) == RET_SUCCESS)
			{
				std::string id = session_id;
				id += ".";
				id += token[i];
				Set_Ox_Storage(NULL, id.c_str(), keyValue, timeout);
			}

			i++; if (i >= MAX_ATTR_NUM) break;		
		}

		return timeout;
	}

	return -1;
}

/*
* Obtain PAT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#obtain_pat
*/
int ox_obtain_pat(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	double keyIntValue;
	int ret;
	int responseLen;
	char tmp[5];

	char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
	char *client_secret = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret");
	char *user_id = "";//"admin";
	char *user_secret = "";//"rootroot";

	ret = oxd_obtain_pat(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, \
		s_cfg->OpenIDProvider, s_cfg->UmaAuthorizationServer, s_cfg->OpenIDClientRedirectURIs, \
		client_id, client_secret, user_id, user_secret, responseStr);

	if (client_id) free(client_id);
	if (client_secret) free(client_secret);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		keyIntValue = 0;
		int timeout;
		if (libjson_getKeyValue("data.expires_in_seconds", &keyIntValue) == RET_SUCCESS)
			timeout = (int)keyIntValue;
		else
			return -1;

		if (libjson_getKeyValue("data.pat_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.pat_token", keyValue, timeout);
		else
			return -1;
/*
		if (libjson_getKeyValue("data.pat_refresh_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.pat_refresh_token", keyValue, timeout);
		else
			return -1;

		if (libjson_getKeyValue("data.authorization_code", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.authorization_code", keyValue, timeout);
		else
			return -1;
*/
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Register Resource
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#register_resource
*/
int ox_register_resources(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];
	unsigned i;

	char *pat_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.pat_token");

	if (s_cfg->uma_am_host == NULL)
		return -1;

	std::string res_scope;
	std::vector<std::string> scope_pairs = modox::explode(s_cfg->UmaGetScope, ";");
	for(i=0; i<scope_pairs.size()-1; i++)
	{
		res_scope += "\"";
		res_scope += scope_pairs[i];
		res_scope += "\"";
		res_scope += ",";
	}
	res_scope += "\"";
	res_scope += scope_pairs[i];
	res_scope += "\"";

	ret = oxd_register_resource(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, \
		s_cfg->UmaAuthorizationServer, pat_token, s_cfg->UmaResourceName, res_scope.c_str(), responseStr);

	if (pat_token) free(pat_token);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data._id", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			std::string id = std::string(s_cfg->UmaResourceName);
			id += "_id";
			Set_Ox_Storage(s_cfg->OpenIDClientName, id.c_str(), keyValue, 0);
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Obtain AAT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#obtain_aat
*/
int ox_obtain_aat(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	double keyIntValue;
	int ret;
	int responseLen;
	char tmp[5];

	char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
	char *client_secret = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret");
	char *user_id = "";
	char *user_secret = "";

	ret = oxd_obtain_aat(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, \
		s_cfg->OpenIDProvider, s_cfg->UmaAuthorizationServer, s_cfg->OpenIDClientRedirectURIs, \
		client_id, client_secret, user_id, user_secret, responseStr);

	if (client_id) free(client_id);
	if (client_secret) free(client_secret);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		keyIntValue = 0;
		int timeout;
		if (libjson_getKeyValue("data.expires_in_seconds", &keyIntValue) == RET_SUCCESS)
			timeout = (int)keyIntValue;
		else
			return -1;

		if (libjson_getKeyValue("data.aat_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.aat_token", keyValue, timeout);
		else
			return -1;
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Obtain RPT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#obtain_rpt
*/
int ox_obtain_rpt(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];

	char *aat_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.aat_token");

	if (s_cfg->uma_am_host == NULL)
		return -1;

	ret = oxd_obtain_rpt(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, aat_token, s_cfg->uma_am_host, responseStr);

	if (aat_token) free(aat_token);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data.rpt_token", keyValue, BUF_SIZE) == RET_SUCCESS)
			Set_Ox_Storage(s_cfg->OpenIDClientName, "uma.rpt_token", keyValue, 0);
		else
			return -1;
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Register permission ticket
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#register_permission_ticket
*/
int ox_register_ticket(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];
	unsigned i = 1;

	char *pat_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.pat_token");
	std::string id = std::string(s_cfg->UmaResourceName);
	id += "_id";
	char *resource_set_id = Get_Ox_Storage(s_cfg->OpenIDClientName, id.c_str());

	if (s_cfg->uma_am_host == NULL)
		return -1;

	std::string res_scope;
	std::vector<std::string> scope_pairs = modox::explode(s_cfg->UmaGetScope, ";");
	for(i=0; i<scope_pairs.size()-1; i++)
	{
		res_scope += "\"";
		res_scope += scope_pairs[i];
		res_scope += "\"";
		res_scope += ",";
	}
	res_scope += "\"";
	res_scope += scope_pairs[i];
	res_scope += "\"";

	ret = oxd_register_ticket(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, s_cfg->UmaAuthorizationServer, pat_token, \
		s_cfg->uma_am_host, s_cfg->uma_rs_host, res_scope.c_str(), resource_set_id, responseStr);

	if (pat_token) free(pat_token);
	if (resource_set_id) free(resource_set_id);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("data.ticket", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			std::string resource_ticket = std::string(s_cfg->UmaResourceName);
			resource_ticket += "_ticket";
			Set_Ox_Storage(s_cfg->OpenIDClientName, resource_ticket.c_str(), keyValue, 0);

			return 0;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return -1;
}

/*
* Authorize RPT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#authorize_rpt
*/
int ox_authorize_rpt(mod_ox_config *s_cfg, const char *session_id)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];

	char *aat_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.aat_token");
	char *rpt_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.rpt_token");
	std::string resource_ticket = std::string(s_cfg->UmaResourceName);
	resource_ticket += "_ticket";
	char *ticket = Get_Ox_Storage(s_cfg->OpenIDClientName, resource_ticket.c_str());

	std::string claim_list = "";
	if(session_id != NULL) 
	{
		// Make Claim string
		{
			char *token[MAX_ATTR_NUM];
			char uma_claims_str[1024];
			int i = 0;
			std::string attr_name;

			for (i=0; i<MAX_ATTR_NUM; i++)
				token[i] = NULL;

			strcpy(uma_claims_str, s_cfg->uma_sent_user_claims);
			i = 0;
			token[i] = strtok(uma_claims_str, "+");
			while(token[i]!= NULL) 
			{
				i++; if (i >= MAX_ATTR_NUM) break;		
				token[i] = strtok(NULL, "+");
			}

			i = 0;
			while(token[i]!= NULL) {
				attr_name = session_id;
				attr_name += ".";
				attr_name += token[i];

				char *claim = NULL;
				claim = Get_Ox_Storage(NULL, attr_name.c_str());
				if (claim != NULL)
				{
					if (claim_list != "")
						claim_list += ",";
					claim_list += "\"";
					claim_list += token[i];
					claim_list += "\"";
					claim_list += ":";
					claim_list += "[\"";
					claim_list += claim;
					claim_list += "\"]";
					free(claim);
				}
				i++; if (i >= MAX_ATTR_NUM) break;		
			}
		}
	}
	else
		return -1;

	ret = oxd_authorize_rpt_token(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, aat_token, \
		rpt_token, s_cfg->uma_am_host, ticket, claim_list.c_str(), responseStr);

	if (aat_token) free(aat_token);
	if (rpt_token) free(rpt_token);
	if (ticket) free(ticket);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Check status of RPT
* http://ox.gluu.org/doku.php?id=oxd:communication_protocol#check_status_of_rpt
*/
int ox_check_rpt_status(mod_ox_config *s_cfg)
{
#define BUF_SIZE 8192
	char responseStr[BUF_SIZE];
	char keyValue[BUF_SIZE];
	int ret;
	int responseLen;
	char tmp[5];

	char *pat_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.pat_token");
	char *rpt_token = Get_Ox_Storage(s_cfg->OpenIDClientName, "uma.rpt_token");

	ret = oxd_check_rpt_status(s_cfg->OxdHostAddr, s_cfg->OxdPortNum, s_cfg->UmaAuthorizationServer, pat_token, rpt_token, responseStr);

	if (pat_token) free(pat_token);
	if (rpt_token) free(rpt_token);

	if (ret == RET_FAILURE)
		return -1;

	memcpy(tmp, responseStr, 4); tmp[4] = 0;
	responseLen = atoi(tmp);
	if (libjson_init(&responseStr[4], responseLen) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("status", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			if (strcmp(keyValue, "ok"))
				return -1;
		}
		else
		{
			return -1;
		}

		bool keyBoolValue=false;
		if (libjson_getKeyValue("data.active", &keyBoolValue) == RET_SUCCESS)
		{
			if (keyBoolValue != true)
				return -1;
		}
		else
		{
			double keyIntValue = 0;
			if (libjson_getKeyValue("data.expires_at", &keyIntValue) == RET_SUCCESS)
			{
				time_t rawtime;
				time (&rawtime);
				if (rawtime < (time_t)keyIntValue)
					return -1;
				else
					return 0;
			}
			else
			{
				return -1;
			}
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

/*
* Get Id token in Authorization Code Flow
* https://seed.gluu.org/oxauth-rp/home.seam?session_id=b3f373c5-8265-4e5f-8314-ecddc3a7379f&scope=openid+profile+address+email&auth_mode=basic&state&code=cafa0a8c-88db-444b-9e6d-ba7090bc6abd&auth_level=10
*/
static char *bufTokenResponse = NULL;
static int lenBufTokenResponse = 0;

size_t writeCallback(char* buf, size_t size, size_t nmemb, void* up)
{ //callback must have this declaration
	//buf is a pointer to the data that curl has for us
	//size*nmemb is the size of the buffer

	if (buf[0] == '{')
	{
		bufTokenResponse = (char *)malloc(size*nmemb);
		if (bufTokenResponse == NULL)
		{
			lenBufTokenResponse = 0;
			return 0;
		}
		memcpy(bufTokenResponse, buf, size*nmemb);
		lenBufTokenResponse = size*nmemb;
	}

	return size*nmemb; //tell curl how many bytes we handled
}

int ox_get_id_token(mod_ox_config *s_cfg, const char *code, const char *redirect_uri, std::string& id_token, std::string& access_token, int *expire_in)
{
#define BUF_SIZE 8192
	if (!code || !redirect_uri)
	{
		return -1;
	}

	char *token_endpoint = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.token_endpoint");
	char *client_id = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_id");
	char *client_secret = Get_Ox_Storage(s_cfg->OpenIDClientName, "oxd.client_secret");

	if ((token_endpoint==NULL) || (client_id==NULL) || (client_secret==NULL))
	{
		if (token_endpoint) free(token_endpoint);
		if (client_id) free(client_id);
		if (client_secret) free(client_secret);

		return -1;
	}

	char authorization_in[1024], *authorization_out;
	long len_in, len_out;
	sprintf(authorization_in, "%s:%s", client_id, client_secret);
	len_in = strlen(authorization_in);
	opkele::util::encode_base64((unsigned char *)authorization_in, len_in, (unsigned char **)&authorization_out, &len_out);
	sprintf(authorization_in, "Basic %s", authorization_out);
	free(authorization_out);

	char query[1024];
	sprintf(query, "grant_type=authorization_code&code=%s&redirect_uri=%s", code, redirect_uri);

	//////////////////////////////////////////////////////////////////////////

	CURL *curl;
	CURLcode res;
	curl_slist* responseHeaders = NULL;
	char headerLine[1024];

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(curl) {
		const int timeout = 30000;

		curl_easy_setopt(curl, CURLOPT_URL, token_endpoint);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

		curl_easy_setopt(curl, CURLOPT_HEADER, 1);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeCallback);

		responseHeaders = curl_slist_append( responseHeaders , "Content-Type: application/x-www-form-urlencoded" );
		sprintf(headerLine, "Authorization: %s", authorization_in);
		responseHeaders = curl_slist_append( responseHeaders , headerLine );
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER , responseHeaders ) ;

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(query));
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout/1000);

		if (bufTokenResponse)
			free(bufTokenResponse);
		bufTokenResponse = NULL;
		lenBufTokenResponse = 0;
		res = curl_easy_perform(curl);
		if(CURLE_OK != res)
			return -1;

		if (bufTokenResponse == NULL)
			return -1;

		// cleanup when done
		curl_slist_free_all( responseHeaders ) ;
		curl_easy_cleanup(curl);
	}


	if (token_endpoint) free(token_endpoint);
	if (client_id) free(client_id);
	if (client_secret) free(client_secret);

	curl_global_cleanup();

	//////////////////////////////////////////////////////////////////////////
	char keyValue[BUF_SIZE];

	if (libjson_init(bufTokenResponse, lenBufTokenResponse) == RET_SUCCESS)
	{
		if (libjson_getKeyValue("access_token", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			access_token = keyValue;
		}
		else
		{
			return -1;
		}

		if (libjson_getKeyValue("id_token", keyValue, BUF_SIZE) == RET_SUCCESS)
		{
			id_token = keyValue;
		}
		else
		{
			return -1;
		}

		double keyIntValue = 0;
		if (libjson_getKeyValue("expires_in", &keyIntValue) == RET_SUCCESS)
		{
			*expire_in = (int)keyIntValue;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}