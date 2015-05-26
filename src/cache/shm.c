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
 * caching using a shared memory backend, FIFO-style
 * based on mod_auth_mellon code
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#ifdef WIN32
#include "stdint.h"
#endif

#include "../mod_auth_ox.h"

extern module AP_MODULE_DECLARE_DATA auth_ox_module;

typedef struct ox_cache_cfg_shm_t {
	apr_shm_t *shm;
	ox_cache_mutex_t *mutex;
} ox_cache_cfg_shm_t;

/* size of key in cached key/value pairs */
#define OX_CACHE_SHM_KEY_MAX 512

/* represents one (fixed size) cache entry, cq. name/value string pair */
typedef struct ox_cache_shm_entry_t {
	/* name of the cache entry */
	char section_key[OX_CACHE_SHM_KEY_MAX];
	/* last (read) access timestamp */
	apr_time_t access;
	/* expiry timestamp */
	apr_time_t expires;
	/* value of the cache entry */
	char value[];
} ox_cache_shm_entry_t;

/* create the cache context */
static void *ox_cache_shm_cfg_create(apr_pool_t *pool) {
	ox_cache_cfg_shm_t *context = (ox_cache_cfg_shm_t *)apr_pcalloc(pool,
			sizeof(ox_cache_cfg_shm_t));
	context->shm = NULL;
	context->mutex = ox_cache_mutex_create(pool);
	return context;
}

#define OX_CACHE_SHM_ADD_OFFSET(t, size) t = (ox_cache_shm_entry_t *)((uint8_t *)t + size)

/*
 * initialized the shared memory block in the parent process
 */
int ox_cache_shm_post_config(server_rec *s) {
	ox_cfg *cfg = (ox_cfg *) ap_get_module_config(s->module_config,
			&auth_ox_module);

	if (cfg->cache_cfg != NULL)
		return APR_SUCCESS;
	ox_cache_cfg_shm_t *context = (ox_cache_cfg_shm_t *)ox_cache_shm_cfg_create(s->process->pool);
	cfg->cache_cfg = context;

	/* create the shared memory segment */
	apr_status_t rv = apr_shm_create(&context->shm,
			cfg->cache_shm_entry_size_max * cfg->cache_shm_size_max,
			NULL, s->process->pool);
	if (rv != APR_SUCCESS) {
		ox_serror(s, "apr_shm_create failed to create shared memory segment");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the whole segment to '/0' */
	int i;
	ox_cache_shm_entry_t *t = (ox_cache_shm_entry_t *)apr_shm_baseaddr_get(context->shm);
	for (i = 0; i < cfg->cache_shm_size_max; i++, OX_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {
		t->section_key[0] = '\0';
		t->access = 0;
	}

	if (ox_cache_mutex_post_config(s, context->mutex, "shm") == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	ox_sdebug(s, "initialized shared memory with a cache size (# entries) of: %d, and a max (single) entry size of: %d", cfg->cache_shm_size_max, cfg->cache_shm_entry_size_max);

	return OK;
}

/*
 * initialize the shared memory segment in a child process
 */
int ox_cache_shm_child_init(apr_pool_t *p, server_rec *s) {
	ox_cfg *cfg = (ox_cfg *)ap_get_module_config(s->module_config,
			&auth_ox_module);
	ox_cache_cfg_shm_t *context = (ox_cache_cfg_shm_t *) cfg->cache_cfg;

	/* initialize the lock for the child process */
	return ox_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *ox_cache_shm_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/*
 * get a value from the shared memory cache
 */
static apr_byte_t ox_cache_shm_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	ox_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	ox_cfg *cfg = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);
	ox_cache_cfg_shm_t *context = (ox_cache_cfg_shm_t *) cfg->cache_cfg;

	int i;
	const char *section_key = ox_cache_shm_get_key(r->pool, section, key);

	*value = NULL;

	/* grab the global lock */
	if (ox_cache_mutex_lock(r, context->mutex) == FALSE)
		return FALSE;

	/* get the pointer to the start of the shared memory block */
	ox_cache_shm_entry_t *t = (ox_cache_shm_entry_t *)apr_shm_baseaddr_get(context->shm);

	/* loop over the block, looking for the key */
	for (i = 0; i < cfg->cache_shm_size_max; i++, OX_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {
		const char *tablekey = t->section_key;

		if ( (tablekey != NULL) && (apr_strnatcmp(tablekey, section_key) == 0) ) {

			/* found a match, check if it has expired */
			if (t->expires > apr_time_now()) {

				/* update access timestamp */
				t->access = apr_time_now();
				*value = t->value;

			} else {

				/* clear the expired entry */
				t->section_key[0] = '\0';
				t->access = 0;

			}

			/* we safely can break now since we would not have found an expired match twice */
			break;
		}
	}

	/* release the global lock */
	ox_cache_mutex_unlock(r, context->mutex);

	return (*value == NULL) ? FALSE : TRUE;
}

/*
 * store a value in the shared memory cache
 */
static apr_byte_t ox_cache_shm_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	ox_debug(r, "enter, section=\"%s\", key=\"%s\", value size=%llu", section,
			key, value ? (unsigned long long )strlen(value) : 0);

	ox_cfg *cfg = (ox_cfg *)ap_get_module_config(r->server->module_config,
			&auth_ox_module);
	ox_cache_cfg_shm_t *context = (ox_cache_cfg_shm_t *) cfg->cache_cfg;

	ox_cache_shm_entry_t *match, *free, *lru;
	ox_cache_shm_entry_t *t;
	apr_time_t current_time;
	int i;
	apr_time_t age;

	const char *section_key = ox_cache_shm_get_key(r->pool, section, key);

	/* check that the passed in key is valid */
	if (strlen(section_key) > OX_CACHE_SHM_KEY_MAX) {
		ox_error(r, "could not store value since key size is too large (%s)",
				section_key);
		return FALSE;
	}

	/* check that the passed in value is valid */
	if ((value != NULL) && (strlen(value) > (cfg->cache_shm_entry_size_max - sizeof(ox_cache_shm_entry_t)))) {
		ox_error(r, "could not store value since value size is too large (%llu > %lu); consider increasing OXCacheShmEntrySizeMax",
				(unsigned long long)strlen(value), (unsigned long)(cfg->cache_shm_entry_size_max - sizeof(ox_cache_shm_entry_t)));
		return FALSE;
	}

	/* grab the global lock */
	if (ox_cache_mutex_lock(r, context->mutex) == FALSE)
		return FALSE;

	/* get a pointer to the shared memory block */
	t = (ox_cache_shm_entry_t *)apr_shm_baseaddr_get(context->shm);

	/* get the current time */
	current_time = apr_time_now();

	/* loop over the block, looking for the key */
	match = NULL;
	free = NULL;
	lru = t;
	for (i = 0; i < cfg->cache_shm_size_max; i++, OX_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {

		/* see if this slot is free */
		if (t->section_key[0] == '\0') {
			if (free == NULL)
				free = t;
			continue;
		}

		/* see if a value already exists for this key */
		if (apr_strnatcmp(t->section_key, section_key) == 0) {
			match = t;
			break;
		}

		/* see if this slot has expired */
		if (t->expires <= current_time) {
			if (free == NULL)
				free = t;
			continue;
		}

		/* see if this slot was less recently used than the current pointer */
		if (t->access < lru->access) {
			lru = t;
		}

	}

	/* if we have no free slots, issue a warning about the LRU entry */
	if (match == NULL && free == NULL) {
		age = (current_time - lru->access) / 1000000;
		if (age < 3600) {
			ox_warn(r,
					"dropping LRU entry with age = %" APR_TIME_T_FMT "s, which is less than one hour; consider increasing the shared memory caching space (which is %d now) with the (global) OXCacheShmMax setting.",
					age, cfg->cache_shm_size_max);
		}
	}

	/* pick the best slot: choose one with a matching key over a free slot, over a least-recently-used one */
	t = match ? match : (free ? free : lru);

	/* see if we need to clear or set the value */
	if (value != NULL) {

		/* fill out the entry with the provided data */
		strcpy(t->section_key, section_key);
		strcpy(t->value, value);
		t->expires = expiry;
		t->access = current_time;

	} else {

		t->section_key[0] = '\0';
		t->access = 0;

	}

	/* release the global lock */
	ox_cache_mutex_unlock(r, context->mutex);

	return TRUE;
}

static int ox_cache_shm_destroy(server_rec *s) {
	ox_cfg *cfg = (ox_cfg *) ap_get_module_config(s->module_config,
			&auth_ox_module);
	ox_cache_cfg_shm_t *context = (ox_cache_cfg_shm_t *) cfg->cache_cfg;
	apr_status_t rv = APR_SUCCESS;

	if (context->shm) {
		rv = apr_shm_destroy(context->shm);
		ox_sdebug(s, "apr_shm_destroy returned: %d", rv);
		context->shm = NULL;
	}

	ox_cache_mutex_destroy(s, context->mutex);

	return rv;
}

ox_cache_t ox_cache_shm = {
		ox_cache_shm_cfg_create,
		ox_cache_shm_post_config,
		ox_cache_shm_child_init,
		ox_cache_shm_get,
		ox_cache_shm_set,
		ox_cache_shm_destroy
};
