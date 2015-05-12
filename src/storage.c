
#include "mod_auth_ox.h"
#include "memcache.h"

#define MAX_FILED_LENGTH 2048

static bool memcached_init_flag = false;

using std::string;

static string replaceAll(const string &str, const string &pattern, const string &replace)   

{   

	string result = str;   

	string::size_type pos = 0;   

	string::size_type offset = 0;   

	while((pos = result.find(pattern, offset)) != string::npos)   
	{   

		result.replace(result.begin() + pos, result.begin() + pos + pattern.size(), replace);   

		offset = pos + replace.size();   

	}   

	return result;   

}


int Init_Ox_Storage(const char *memcache_addr, const int memcache_portnum)
{
	if (memcached_init_flag == true)
	{
		return 0;
	}

	if (memcache_init((char *)memcache_addr, memcache_portnum) == 0)
	{
		memcached_init_flag = true;
		return 0;
	}

	return -1;
}

int Set_Ox_Storage(const char *key_name, const char *key_param, const char *val, int lifespan) 
{
	string key;

	if ((!key_param) || (!val))
		return -1;

	if (!key_name)
	{
		key = key_param;
	}
	else
	{
		key = key_name;
		key += ".";
		key += key_param;
	}

	key = replaceAll(key, " ", ".");
	// lifespan will be 0 if not specified by user in config - so lasts as long as browser is open.  In this case, make it last for up to a week.
	time_t expires_on = (lifespan <= 0) ? (86400*30) : (lifespan);
	memcache_delete(key.c_str());
	if (memcache_set_timeout(key.c_str(), val, (unsigned int)expires_on) == 0)
	{
		return 0;
	}

	return -1;
}

char *Get_Ox_Storage(const char *key_name, const char *key_param) 
{
	string key;

	if (!key_param)
		return NULL;

	if (!key_name)
	{
		key = key_param;
	}
	else
	{
		key = key_name;
		key += ".";
		key += key_param;
	}

	key = replaceAll(key, " ", ".");
	char *val = memcache_get(key.c_str());
	if(val == NULL) 
		return NULL;

	char *retString = NULL;
	retString = (char *)malloc(MAX_FILED_LENGTH);
	if (retString == NULL) return NULL;
	
	strcpy(retString, val);

	return retString;
}

int Remove_Ox_Storage(const char *key_name, const char *key_param) 
{
	return Set_Ox_Storage(key_name, key_param, " ", 1);
}

void Close_Ox_Storage()
{
	memcache_destroy();
}
