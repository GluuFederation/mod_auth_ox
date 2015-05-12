
#ifndef __MOD_STORAGE_H_
#define __MOD_STORAGE_H_

int Init_Ox_Storage(const char *memcache_addr, const int memcache_portnum);
int Set_Ox_Storage(const char *key_name, const char *key_param, const char *val, int lifespan);
char *Get_Ox_Storage(const char *key_name, const char *key_param);
int Remove_Ox_Storage(const char *key_name, const char *key_param);
void Close_Ox_Storage();

#endif
