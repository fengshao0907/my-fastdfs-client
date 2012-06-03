#include "my_fdfs_client.h"
#include "tracker_client.h"
#include "storage_client1.h"

int my_client_init(MyClientContext *pContext, const char *fastdfs_conf_filename, 
	const char *fastdht_conf_filename)
{
	int result;
	if ((result=fdfs_client_init_ex(&(pContext->fdfs.tracker_group), 
		fastdfs_conf_filename)) != 0)
	{
		return result;
	}

	if ((result=fdht_load_conf(fastdht_conf_filename, 
		&(pContext->fdht.group_array), 
		&(pContext->fdht.keep_alive))) != 0)
	{
		return result;
	}

	return 0;
}

void my_client_destroy(MyClientContext *pContext)
{
	tracker_close_all_connections_ex(&(pContext->fdfs.tracker_group));
	fdfs_client_destroy_ex(&(pContext->fdfs.tracker_group));

	fdht_client_destroy(&(pContext->fdht.group_array));
}

static void my_fdfs_fill_key_info(FDHTKeyInfo *pKeyInfo, \
		MyClientContext *pContext, const char *my_file_id)
{
	pKeyInfo->namespace_len = pContext->fdht.namespace_len;
	memcpy(pKeyInfo->szNameSpace, pContext->fdht.szNameSpace, \
		pContext->fdht.namespace_len + 1);

	pKeyInfo->obj_id_len = strlen(my_file_id);
	if (pKeyInfo->obj_id_len > FDHT_MAX_OBJECT_ID_LEN)
	{
		pKeyInfo->obj_id_len = FDHT_MAX_OBJECT_ID_LEN;
	}
	memcpy(pKeyInfo->szObjectId, my_file_id, pKeyInfo->obj_id_len + 1);

	pKeyInfo->key_len = sizeof(MY_CLIENT_FILE_ID_KEY_NAME) - 1;
	memcpy(pKeyInfo->szKey, MY_CLIENT_FILE_ID_KEY_NAME, pKeyInfo->key_len + 1);
}

int my_fdfs_upload_by_filename_ex(MyClientContext *pContext, \
		const char *my_file_id, const char cmd, \
		const char *local_filename, const char *file_ext_name, \
		const char *group_name)
{
	FDHTKeyInfo keyInfo;
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	char new_group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
	char remote_filename[128];
	char *p;
	TrackerServerInfo *pTrackerServer;
	TrackerServerInfo *pStorageServer = NULL;
	int value_len;
	int result;

	my_fdfs_fill_key_info(&keyInfo, pContext, my_file_id);
	p = fdfs_file_id;
	value_len = sizeof(fdfs_file_id);
	result = fdht_get(&keyInfo, &p, &value_len);
	if (result == 0)
	{
		return EEXIST;
	}
	else if (result != ENOENT)
	{
		return result;
	}

	pTrackerServer = tracker_get_connection_ex( \
					&(pContext->fdfs.tracker_group));
	if (pTrackerServer == NULL)
	{
		return errno != 0 ? errno : ECONNREFUSED;
	}

	if (group_name == NULL)
	{
		*new_group_name = '\0';
	}
	else
	{
		snprintf(new_group_name, sizeof(new_group_name), \
			"%s", group_name);
	}

	result = storage_upload_by_filename_ex(pTrackerServer, \
			pStorageServer, 0, cmd, local_filename, \
			file_ext_name, NULL, 0, new_group_name, remote_filename);
	if (result != 0)
	{
		return result;
	}

	value_len = sprintf(fdfs_file_id, "%s%c%s", new_group_name, \
			FDFS_FILE_ID_SEPERATOR, remote_filename);
	if ((result=fdht_set(&keyInfo, FDHT_EXPIRES_NEVER, fdfs_file_id, \
			value_len)) != 0)
	{
		storage_delete_file1(pTrackerServer, pStorageServer, \
			fdfs_file_id);  //rollback
		return result;
	}

	return 0;
}

