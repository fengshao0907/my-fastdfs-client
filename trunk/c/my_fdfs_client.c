#include <errno.h>
#include "logger.h"
#include "my_fdfs_client.h"
#include "tracker_client.h"
#include "storage_client1.h"

int my_client_init(MyClientContext *pContext, const char *szFDHTNameSpace, 
	const char *fastdfs_conf_filename, const char *fastdht_conf_filename)
{
	int result;

	if (szFDHTNameSpace == NULL || *szFDHTNameSpace == '\0')
	{
		logError("file: "__FILE__", line: %d, " \
			"namespace is empty!", __LINE__);
		return EINVAL;
	}

	memset(pContext, 0, sizeof(MyClientContext));
	pContext->fdht.namespace_len = strlen(szFDHTNameSpace);
	if (pContext->fdht.namespace_len > FDHT_MAX_NAMESPACE_LEN)
	{
		pContext->fdht.namespace_len = FDHT_MAX_NAMESPACE_LEN;
	}
	memcpy(pContext->fdht.szNameSpace, szFDHTNameSpace,
		pContext->fdht.namespace_len + 1);

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

int my_fdfs_copy_context(MyClientContext *pDestContext, \
	MyClientContext *pSrcContext)
{
	int result;
	if ((result=fdfs_copy_tracker_group(&(pDestContext->fdfs.tracker_group),
		&(pSrcContext->fdfs.tracker_group))) != 0)
	{
		return result;
	}

	if ((result=fdht_copy_group_array(&(pDestContext->fdht.group_array), \
		&(pSrcContext->fdht.group_array))) != 0)
	{
		return result;
	}

	pDestContext->fdht.keep_alive = pSrcContext->fdht.keep_alive;
	pDestContext->fdht.namespace_len = pSrcContext->fdht.namespace_len;
	memcpy(pDestContext->fdht.szNameSpace, pSrcContext->fdht.szNameSpace, \
		pSrcContext->fdht.namespace_len + 1);

	return 0;
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

#define GET_TRACKER_CONNECTION(pTrackerServer, pContext) \
	do { \
	pTrackerServer = tracker_get_connection_ex( \
					&(pContext->fdfs.tracker_group)); \
	if (pTrackerServer == NULL) \
	{ \
		return errno != 0 ? errno : ECONNREFUSED; \
	} \
	} while (0)

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
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int value_len;
	int result;

	my_fdfs_fill_key_info(&keyInfo, pContext, my_file_id);
	p = fdfs_file_id;
	value_len = sizeof(fdfs_file_id);
	result = fdht_get_ex1(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NONE, \
		&p, &value_len, malloc);
	if (result == 0)
	{
		return EEXIST;
	}
	else if (result != ENOENT)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

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
	if ((result=fdht_set_ex(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NEVER, \
		fdfs_file_id, value_len)) != 0)
	{
		storage_delete_file1(pTrackerServer, pStorageServer, \
			fdfs_file_id);  //rollback
		return result;
	}

	return 0;
}

int my_fdfs_do_upload_file(MyClientContext *pContext, const char *my_file_id, \
	const char cmd, const int upload_type, const char *file_buff, \
	void *arg, const int64_t file_size, const char *file_ext_name, \
	const char *group_name)
{
	FDHTKeyInfo keyInfo;
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	char new_group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
	char remote_filename[128];
	char *p;
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	const char *master_filename = NULL;
	const char *prefix_name = NULL;
	int value_len;
	int result;

	my_fdfs_fill_key_info(&keyInfo, pContext, my_file_id);
	p = fdfs_file_id;
	value_len = sizeof(fdfs_file_id);
	result = fdht_get_ex1(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NONE, \
		&p, &value_len, malloc);
	if (result == 0)
	{
		return EEXIST;
	}
	else if (result != ENOENT)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	if (group_name == NULL)
	{
		*new_group_name = '\0';
	}
	else
	{
		snprintf(new_group_name, sizeof(new_group_name), \
			"%s", group_name);
	}

	result = storage_do_upload_file(pTrackerServer, pStorageServer, \
			0, cmd, upload_type, file_buff, arg, file_size, \
			master_filename, prefix_name, file_ext_name, NULL, 0, \
			new_group_name, remote_filename);
	if (result != 0)
	{
		return result;
	}

	value_len = sprintf(fdfs_file_id, "%s%c%s", new_group_name, \
			FDFS_FILE_ID_SEPERATOR, remote_filename);
	if ((result=fdht_set_ex(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NEVER, \
		fdfs_file_id, value_len)) != 0)
	{
		storage_delete_file1(pTrackerServer, pStorageServer, \
			fdfs_file_id);  //rollback
		return result;
	}

	return 0;
}

int my_fdfs_upload_by_callback_ex(MyClientContext *pContext, \
		const char *my_file_id, const char cmd, \
		UploadCallback callback, void *arg, \
		const int64_t file_size, const char *file_ext_name, \
		const char *group_name)
{
	FDHTKeyInfo keyInfo;
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	char new_group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
	char remote_filename[128];
	char *p;
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int value_len;
	int result;

	my_fdfs_fill_key_info(&keyInfo, pContext, my_file_id);
	p = fdfs_file_id;
	value_len = sizeof(fdfs_file_id);
	result = fdht_get_ex1(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NONE, \
		&p, &value_len, malloc);
	if (result == 0)
	{
		return EEXIST;
	}
	else if (result != ENOENT)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	if (group_name == NULL)
	{
		*new_group_name = '\0';
	}
	else
	{
		snprintf(new_group_name, sizeof(new_group_name), \
			"%s", group_name);
	}

	result = storage_upload_by_callback_ex(pTrackerServer, pStorageServer, \
			0, cmd, callback, arg, file_size, file_ext_name, NULL, \
			0, new_group_name, remote_filename);
	if (result != 0)
	{
		return result;
	}

	value_len = sprintf(fdfs_file_id, "%s%c%s", new_group_name, \
			FDFS_FILE_ID_SEPERATOR, remote_filename);
	if ((result=fdht_set_ex(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NEVER, \
		fdfs_file_id, value_len)) != 0)
	{
		storage_delete_file1(pTrackerServer, pStorageServer, \
			fdfs_file_id);  //rollback
		return result;
	}

	return 0;
}

int my_fdfs_delete_file(MyClientContext *pContext, const char *my_file_id)
{
	FDHTKeyInfo keyInfo;
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128];
	char *p;
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;
	int value_len;

	my_fdfs_fill_key_info(&keyInfo, pContext, my_file_id);
	p = fdfs_file_id;
	value_len = sizeof(fdfs_file_id);
	result = fdht_get_ex1(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NONE, \
		&p, &value_len, malloc);
	if (result != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	if ((result=storage_delete_file1(pTrackerServer, pStorageServer,
		fdfs_file_id)) == 0)
	{
		if (fdht_delete_ex(&(pContext->fdht.group_array), \
			pContext->fdht.keep_alive, &keyInfo) != 0)
		{
			logError("file: "__FILE__", line: %d, " \
				"delete key: %s of object: %s fail, " \
				"errno: %d, error info: %s", __LINE__, \
				MY_CLIENT_FILE_ID_KEY_NAME, my_file_id, \
				errno, STRERROR(errno));
		}
	}

	return result;
}

int my_fdfs_get_file_id(MyClientContext *pContext, const char *my_file_id, \
		char *fdfs_file_id, const int file_id_size)
{
	FDHTKeyInfo keyInfo;
	char *p;
	int value_len;

	my_fdfs_fill_key_info(&keyInfo, pContext, my_file_id);
	p = fdfs_file_id;
	value_len = file_id_size;
	return fdht_get_ex1(&(pContext->fdht.group_array), \
		pContext->fdht.keep_alive, &keyInfo, FDHT_EXPIRES_NONE, \
		&p, &value_len, malloc);
}

int my_fdfs_do_download_file_ex(MyClientContext *pContext, \
		const int download_type, const char *my_file_id, \
		const int64_t file_offset, const int64_t download_bytes, \
		char **file_buff, void *arg, int64_t *file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_file_id, fdfs_file_id, \
		sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_do_download_file1_ex(pTrackerServer, pStorageServer, \
		download_type, fdfs_file_id, file_offset, download_bytes, \
		file_buff, arg, file_size);
}

int my_fdfs_download_file_to_file(MyClientContext *pContext, \
		const char *my_file_id, const char *local_filename, \
		int64_t *file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_file_id, fdfs_file_id, \
		sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_download_file_to_file1(pTrackerServer, pStorageServer, \
		fdfs_file_id, local_filename, file_size);
}

int my_fdfs_download_file_ex(MyClientContext *pContext, const char *my_file_id, \
		const int64_t file_offset, const int64_t download_bytes, \
		DownloadCallback callback, void *arg, int64_t *file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_file_id, fdfs_file_id, \
		sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_download_file_ex1(pTrackerServer, pStorageServer, \
		fdfs_file_id, file_offset, download_bytes, \
		callback, arg, file_size);
}

int my_fdfs_append_by_filename(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		const char *local_filename)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_appender_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_append_by_filename1(pTrackerServer, pStorageServer, \
		local_filename, fdfs_file_id);
}

int my_fdfs_append_by_filebuff(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		const char *file_buff, const int64_t file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_appender_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_append_by_filebuff1(pTrackerServer, pStorageServer, \
		file_buff, file_size, fdfs_file_id);
}

int my_fdfs_append_by_callback(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		UploadCallback callback, void *arg, const int64_t file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_appender_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_append_by_callback1(pTrackerServer, pStorageServer, \
		callback, arg, file_size, fdfs_file_id);
}

int my_fdfs_modify_by_filename(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		const char *local_filename, const int64_t file_offset)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_appender_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_modify_by_filename1(pTrackerServer, pStorageServer, \
		local_filename, file_offset, fdfs_file_id);
}

int my_fdfs_modify_by_filebuff(MyClientContext *pContext, \
		const char *my_appender_file_id, const char *file_buff, \
		const int64_t file_offset, const int64_t file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_appender_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_modify_by_filebuff1(pTrackerServer, pStorageServer, \
		file_buff, file_offset, file_size, fdfs_file_id);
}

int my_fdfs_modify_by_callback(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		UploadCallback callback, void *arg, \
		const int64_t file_offset, const int64_t file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_appender_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_modify_by_callback1(pTrackerServer, pStorageServer, \
		callback, arg, file_offset, file_size, fdfs_file_id);
}

int my_fdfs_truncate_file(MyClientContext *pContext, \
	const char *my_appender_file_id, const int64_t truncated_file_size)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_appender_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_truncate_file1(pTrackerServer, pStorageServer, \
		fdfs_file_id, truncated_file_size);
}

int my_fdfs_query_file_info_ex(MyClientContext *pContext, \
		const char *my_file_id, FDFSFileInfo *pFileInfo, \
		const bool bSilence)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_query_file_info_ex1(pTrackerServer, pStorageServer, \
		fdfs_file_id, pFileInfo, bSilence);
}

int my_fdfs_get_file_info_ex(MyClientContext *pContext, \
		const char *my_file_id, const bool get_from_server, \
		FDFSFileInfo *pFileInfo)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	return fdfs_get_file_info_ex1(fdfs_file_id, get_from_server, pFileInfo);
}

int my_fdfs_file_exist(MyClientContext *pContext, const char *my_file_id)
{
	char fdfs_file_id[FDFS_GROUP_NAME_MAX_LEN + 128]; \
	ConnectionInfo *pTrackerServer;
	ConnectionInfo *pStorageServer = NULL;
	int result;

	if ((result=my_fdfs_get_file_id(pContext, my_file_id, \
		fdfs_file_id, sizeof(fdfs_file_id))) != 0)
	{
		return result;
	}

	GET_TRACKER_CONNECTION(pTrackerServer, pContext);

	return storage_file_exist1(pTrackerServer, pStorageServer, \
		fdfs_file_id);
}

