#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>

#ifdef ZTS
#include "TSRM.h"
#endif

#include <SAPI.h>
#include <php_ini.h>
#include "ext/standard/info.h"
#include <zend_extensions.h>
#include <zend_exceptions.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include "logger.h"
#include "sockopt.h"
#include "fdfs_global.h"
#include "fdht_global.h"
#include "tracker_client.h"
#include "shared_func.h"
#include "client_global.h"
#include "my_fdfs_client.h"
#include "php_my_fastdfs_client.h"

typedef struct
{
	MyClientContext *pMyClientContext;
} FDFSConfigInfo;

typedef struct
{
	MyClientContext *pMyClientContext;
	int err_no;
} FDFSPhpContext;

typedef struct
{
        zend_object zo;
        FDFSConfigInfo *pConfigInfo;
	FDFSPhpContext context;
} php_fdfs_t;

typedef struct
{
	zval *func_name;
	zval *args;
} php_fdfs_callback_t;

typedef struct
{
	php_fdfs_callback_t callback;
	int64_t file_size;
} php_fdfs_upload_callback_t;

/*
static int php_fdfs_download_callback(void *arg, const int64_t file_size, \
		const char *data, const int current_size);
*/

static FDFSConfigInfo *config_list = NULL;
static int config_count = 0;

static zend_class_entry *fdfs_ce = NULL;
static zend_class_entry *fdfs_exception_ce = NULL;

#if HAVE_SPL
static zend_class_entry *spl_ce_RuntimeException = NULL;
#endif

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
const zend_fcall_info empty_fcall_info = { 0, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0 };
#undef ZEND_BEGIN_ARG_INFO_EX
#define ZEND_BEGIN_ARG_INFO_EX(name, pass_rest_by_reference, return_reference, required_num_args) \
    static zend_arg_info name[] = {                                                               \
        { NULL, 0, NULL, 0, 0, 0, pass_rest_by_reference, return_reference, required_num_args },
#endif


// Every user visible function must have an entry in my_fastdfs_client_functions[].
zend_function_entry my_fastdfs_client_functions[] = {
	ZEND_FE(my_fastdfs_client_version, NULL)
	{NULL, NULL, NULL}  /* Must be the last line */
};

zend_module_entry my_fastdfs_client_module_entry = {
	STANDARD_MODULE_HEADER,
	"my_fastdfs_client",
	my_fastdfs_client_functions,
	PHP_MINIT(my_fastdfs_client),
	PHP_MSHUTDOWN(my_fastdfs_client),
	NULL,//PHP_RINIT(my_fastdfs_client),
	NULL,//PHP_RSHUTDOWN(my_fastdfs_client),
	PHP_MINFO(my_fastdfs_client),
	"1.00", 
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MY_FASTDFS_CLIENT
	ZEND_GET_MODULE(my_fastdfs_client)
#endif

static int php_fdfs_get_callback_from_hash(HashTable *callback_hash, \
		php_fdfs_callback_t *pCallback)
{
	zval **data;
	zval ***ppp;

	data = NULL;
	ppp = &data;
	if (zend_hash_find(callback_hash, "callback", sizeof("callback"), \
			(void **)ppp) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"key \"callback\" not exist!", __LINE__);
		return ENOENT;
	}
	if ((*data)->type != IS_STRING)
	{
		logError("file: "__FILE__", line: %d, " \
			"key \"callback\" is not string type, type=%d!", \
			__LINE__, (*data)->type);
		return EINVAL;
	}
	pCallback->func_name = *data;

	data = NULL;
	if (zend_hash_find(callback_hash, "args", sizeof("args"), \
			(void **)ppp) == FAILURE)
	{
		pCallback->args = NULL;
	}
	else
	{
		pCallback->args = ((*data)->type == IS_NULL) ? NULL : *data;
	}

	return 0;
}

static int php_fdfs_get_upload_callback_from_hash(HashTable *callback_hash, \
		php_fdfs_upload_callback_t *pUploadCallback)
{
	zval **data;
	zval ***ppp;
	int result;

	if ((result=php_fdfs_get_callback_from_hash(callback_hash, \
			&(pUploadCallback->callback))) != 0)
	{
		return result;
	}

	data = NULL;
	ppp = &data;
	if (zend_hash_find(callback_hash, "file_size", sizeof("file_size"), \
			(void **)ppp) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"key \"file_size\" not exist!", __LINE__);
		return ENOENT;
	}
	if ((*data)->type != IS_LONG)
	{
		logError("file: "__FILE__", line: %d, " \
			"key \"file_size\" is not long type, type=%d!", \
			__LINE__, (*data)->type);
		return EINVAL;
	}
	pUploadCallback->file_size = (*data)->value.lval;
	if (pUploadCallback->file_size < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"file_size: "INT64_PRINTF_FORMAT" is invalid!", \
			__LINE__, pUploadCallback->file_size);
		return EINVAL;
	}

	return 0;
}

/*
static void php_fdfs_storage_delete_file_impl( \
		INTERNAL_FUNCTION_PARAMETERS, 
		FDFSPhpContext *pContext)
{
	int argc;
	char *group_name;
	char *remote_filename;
	int group_nlen;
	int filename_len;
	zval *tracker_obj;
	zval *storage_obj;
	HashTable *tracker_hash;
	HashTable *storage_hash;
	TrackerServerInfo tracker_server;
	TrackerServerInfo storage_server;
	TrackerServerInfo *pTrackerServer;
	TrackerServerInfo *pStorageServer;
	int result;
	int min_param_count;
	int max_param_count;
	int saved_tracker_sock;
	int saved_storage_sock;
	char new_file_id[FDFS_GROUP_NAME_MAX_LEN + 128];

	if (bFileId)
	{
		min_param_count = 1;
		max_param_count = 3;
	}
	else
	{
		min_param_count = 2;
		max_param_count = 4;
	}

    	argc = ZEND_NUM_ARGS();
	if (argc < min_param_count || argc > max_param_count)
	{
		logError("file: "__FILE__", line: %d, " \
			"storage_delete_file parameters " \
			"count: %d < %d or > %d", __LINE__, argc, \
			min_param_count, max_param_count);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	tracker_obj = NULL;
	storage_obj = NULL;
	if (bFileId)
	{
		char *pSeperator;
		char *file_id;
		int file_id_len;

		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|aa", \
			&file_id, &file_id_len, &tracker_obj, &storage_obj) \
			== FAILURE)
		{
			logError("file: "__FILE__", line: %d, " \
				"zend_parse_parameters fail!", __LINE__);
			pContext->err_no = EINVAL;
			RETURN_BOOL(false);
		}

		snprintf(new_file_id, sizeof(new_file_id), "%s", file_id);
		pSeperator = strchr(new_file_id, FDFS_FILE_ID_SEPERATOR);
		if (pSeperator == NULL)
		{
			logError("file: "__FILE__", line: %d, " \
				"file_id is invalid, file_id=%s", \
				__LINE__, file_id);
			pContext->err_no = EINVAL;
			RETURN_BOOL(false);
		}

		*pSeperator = '\0';
		group_name = new_file_id;
		remote_filename =  pSeperator + 1;
	}
	else if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|aa", \
		&group_name, &group_nlen, &remote_filename, &filename_len, \
		&tracker_obj, &storage_obj) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"zend_parse_parameters fail!", __LINE__);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	if (tracker_obj == NULL)
	{
		pTrackerServer = tracker_get_connection_ex(pContext->pMyClientContext);
		if (pTrackerServer == NULL)
		{
			pContext->err_no = ENOENT;
			RETURN_BOOL(false);
		}
		saved_tracker_sock = -1;
		tracker_hash = NULL;
	}
	else
	{
		pTrackerServer = &tracker_server;
		tracker_hash = Z_ARRVAL_P(tracker_obj);
		if ((result=php_fdfs_get_server_from_hash(tracker_hash, \
				pTrackerServer)) != 0)
		{
			pContext->err_no = result;
			RETURN_BOOL(false);
		}
		saved_tracker_sock = pTrackerServer->sock;
	}

	if (storage_obj == NULL)
	{
		pStorageServer = NULL;
		storage_hash = NULL;
		saved_storage_sock = -1;
	}
	else
	{
		pStorageServer = &storage_server;
		storage_hash = Z_ARRVAL_P(storage_obj);
		if ((result=php_fdfs_get_server_from_hash(storage_hash, \
				pStorageServer)) != 0)
		{
			pContext->err_no = result;
			RETURN_BOOL(false);
		}
		saved_storage_sock = pStorageServer->sock;
	}

	result = storage_delete_file(pTrackerServer, pStorageServer, \
			group_name, remote_filename);
	if (tracker_hash != NULL && pTrackerServer->sock != \
		saved_tracker_sock)
	{
		CLEAR_HASH_SOCK_FIELD(tracker_hash)
	}
	if (pStorageServer != NULL && pStorageServer->sock != \
		saved_storage_sock)
	{
		CLEAR_HASH_SOCK_FIELD(storage_hash)
	}

	pContext->err_no = result;
	if (result != 0)
	{
		RETURN_BOOL(false);
	}

	RETURN_BOOL(true);
}

static void php_fdfs_storage_download_file_to_callback_impl( \
	INTERNAL_FUNCTION_PARAMETERS, FDFSPhpContext *pContext)
{
	int argc;
	char *group_name;
	char *remote_filename;
	zval *download_callback;
	int group_nlen;
	int filename_len;
	long file_offset;
	long download_bytes;
	int64_t file_size;
	zval *tracker_obj;
	zval *storage_obj;
	HashTable *tracker_hash;
	HashTable *storage_hash;
	TrackerServerInfo tracker_server;
	TrackerServerInfo storage_server;
	TrackerServerInfo *pTrackerServer;
	TrackerServerInfo *pStorageServer;
	HashTable *callback_hash;
	php_fdfs_callback_t php_callback;
	int result;
	int min_param_count;
	int max_param_count;
	int saved_tracker_sock;
	int saved_storage_sock;
	char new_file_id[FDFS_GROUP_NAME_MAX_LEN + 128];

	if (bFileId)
	{
		min_param_count = 2;
		max_param_count = 6;
	}
	else
	{
		min_param_count = 3;
		max_param_count = 7;
	}

    	argc = ZEND_NUM_ARGS();
	if (argc < min_param_count || argc > max_param_count)
	{
		logError("file: "__FILE__", line: %d, " \
			"storage_download_file_to_buff parameters " \
			"count: %d < %d or > %d", __LINE__, argc, \
			min_param_count, max_param_count);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	file_offset = 0;
	download_bytes = 0;
	tracker_obj = NULL;
	storage_obj = NULL;
	if (bFileId)
	{
		char *pSeperator;
		char *file_id;
		int file_id_len;

		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, \
			"sa|llaa", &file_id, &file_id_len, \
			&download_callback, &file_offset, &download_bytes, \
			&tracker_obj, &storage_obj) == FAILURE)
		{
			logError("file: "__FILE__", line: %d, " \
				"zend_parse_parameters fail!", __LINE__);
			pContext->err_no = EINVAL;
			RETURN_BOOL(false);
		}

		snprintf(new_file_id, sizeof(new_file_id), "%s", file_id);
		pSeperator = strchr(new_file_id, FDFS_FILE_ID_SEPERATOR);
		if (pSeperator == NULL)
		{
			logError("file: "__FILE__", line: %d, " \
				"file_id is invalid, file_id=%s", \
				__LINE__, file_id);
			pContext->err_no = EINVAL;
			RETURN_BOOL(false);
		}

		*pSeperator = '\0';
		group_name = new_file_id;
		remote_filename =  pSeperator + 1;
	}
	else if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssa|llaa", \
		&group_name, &group_nlen, &remote_filename, &filename_len, \
		&download_callback, &file_offset, &download_bytes, \
		&tracker_obj, &storage_obj) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"zend_parse_parameters fail!", __LINE__);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	if (tracker_obj == NULL)
	{
		pTrackerServer = tracker_get_connection_ex(pContext->pMyClientContext);
		if (pTrackerServer == NULL)
		{
			pContext->err_no = ENOENT;
			RETURN_BOOL(false);
		}
		saved_tracker_sock = -1;
		tracker_hash = NULL;
	}
	else
	{
		pTrackerServer = &tracker_server;
		tracker_hash = Z_ARRVAL_P(tracker_obj);
		if ((result=php_fdfs_get_server_from_hash(tracker_hash, \
				pTrackerServer)) != 0)
		{
			pContext->err_no = result;
			RETURN_BOOL(false);
		}
		saved_tracker_sock = pTrackerServer->sock;
	}

	if (storage_obj == NULL)
	{
		pStorageServer = NULL;
		storage_hash = NULL;
		saved_storage_sock = -1;
	}
	else
	{
		pStorageServer = &storage_server;
		storage_hash = Z_ARRVAL_P(storage_obj);
		if ((result=php_fdfs_get_server_from_hash(storage_hash, \
				pStorageServer)) != 0)
		{
			pContext->err_no = result;
			RETURN_BOOL(false);
		}
		saved_storage_sock = pStorageServer->sock;
	}

	callback_hash = Z_ARRVAL_P(download_callback);
	result = php_fdfs_get_callback_from_hash(callback_hash, \
				&php_callback);
	if (result != 0)
	{
		pContext->err_no = result;
		RETURN_BOOL(false);
	}

	result = storage_download_file_ex(pTrackerServer, pStorageServer, \
		group_name, remote_filename, file_offset, download_bytes, \
		php_fdfs_download_callback, (void *)&php_callback, &file_size);
	if (tracker_hash != NULL && pTrackerServer->sock != saved_tracker_sock)
	{
		CLEAR_HASH_SOCK_FIELD(tracker_hash)
	}
	if (pStorageServer != NULL && pStorageServer->sock != \
		saved_storage_sock)
	{
		CLEAR_HASH_SOCK_FIELD(storage_hash)
	}

	if (result != 0)
	{
		pContext->err_no = result;
		RETURN_BOOL(false);
	}
	RETURN_BOOL(true);
}
*/

static int php_fdfs_upload_callback(void *arg, const int64_t file_size, int sock)
{
	php_fdfs_upload_callback_t *pUploadCallback;
	zval *args[2];
	zval zsock;
	zval ret;
	zval null_args;
	int result;

	ZVAL_NULL(&ret);
	ZVAL_LONG(&zsock, sock);

	pUploadCallback = (php_fdfs_upload_callback_t *)arg;
	if (pUploadCallback->callback.args == NULL)
	{
		ZVAL_NULL(&null_args);
		pUploadCallback->callback.args = &null_args;
	}
	args[0] = &zsock;
	args[1] = pUploadCallback->callback.args;

	if (call_user_function(EG(function_table), NULL, \
		pUploadCallback->callback.func_name, 
		&ret, 2, args TSRMLS_CC) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"call callback function: %s fail", __LINE__, \
			Z_STRVAL_P(pUploadCallback->callback.func_name));
		return EINVAL;
	}

	if (ret.type == IS_LONG || ret.type == IS_BOOL)
	{
		result = ret.value.lval == 0 ? EFAULT : 0;
	}
	else
	{
		logError("file: "__FILE__", line: %d, " \
			"callback function return invalid value type: %d", \
			__LINE__, ret.type);
		result = EINVAL;
	}

	return result;
}

/*
static int php_fdfs_download_callback(void *arg, const int64_t file_size, \
		const char *data, const int current_size)
{
	php_fdfs_callback_t *pCallback;
	zval *args[3];
	zval zfilesize;
	zval zdata;
	zval ret;
	zval null_args;
	int result;

	ZVAL_NULL(&ret);
	ZVAL_LONG(&zfilesize, file_size);
	ZVAL_STRINGL(&zdata, (char *)data, current_size, 0);

	pCallback = (php_fdfs_callback_t *)arg;
	if (pCallback->args == NULL)
	{
		ZVAL_NULL(&null_args);
		pCallback->args = &null_args;
	}
	args[0] = pCallback->args;
	args[1] = &zfilesize;
	args[2] = &zdata;
	if (call_user_function(EG(function_table), NULL, \
		pCallback->func_name, 
		&ret, 3, args TSRMLS_CC) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"call callback function: %s fail", __LINE__, \
			Z_STRVAL_P(pCallback->func_name));
		return EINVAL;
	}

	if (ret.type == IS_LONG || ret.type == IS_BOOL)
	{
		result = ret.value.lval == 0 ? EFAULT : 0;
	}
	else
	{
		logError("file: "__FILE__", line: %d, " \
			"callback function return invalid value type: %d", \
			__LINE__, ret.type);
		result = EINVAL;
	}

	return result;
}
*/

#define CHECK_MY_FILE_ID_LEN(pContext, my_file_id_len) \
	do \
	{  \
		if (my_file_id_len == 0) \
		{ \
			logError("file: "__FILE__", line: %d, " \
				"my file id is empty!", __LINE__); \
			pContext->err_no = EINVAL; \
			RETURN_BOOL(false); \
		} \
	} while (0)

static void php_my_fdfs_get_file_id_impl( \
	INTERNAL_FUNCTION_PARAMETERS, FDFSPhpContext *pContext)
{
	int argc;
	char *my_file_id;
	char fdfs_file_id[128];
	int my_file_id_len;

	argc = ZEND_NUM_ARGS();
	if (argc != 1)
	{
		logError("file: "__FILE__", line: %d, " \
			"get_file_id parameters count: %d != 1", \
			__LINE__, argc);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	my_file_id = NULL;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, \
		"s", &my_file_id, &my_file_id_len) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"zend_parse_parameters fail!", __LINE__);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	CHECK_MY_FILE_ID_LEN(pContext, my_file_id_len);

	pContext->err_no = my_fdfs_get_file_id(pContext->pMyClientContext, \
		my_file_id, fdfs_file_id, sizeof(fdfs_file_id));
	if (pContext->err_no != 0)
	{
		RETURN_BOOL(false);
	}

	RETURN_STRINGL(fdfs_file_id, strlen(fdfs_file_id), 1);
}

static void php_my_fdfs_upload_file_impl(INTERNAL_FUNCTION_PARAMETERS, \
		FDFSPhpContext *pContext, const byte cmd, \
		const byte upload_type)
{
	int result;
	int argc;
	char *my_file_id;
	int my_file_id_len;
	char *local_filename;
	int filename_len;
	char *file_ext_name;
	zval *callback_obj;
	zval *ext_name_obj;
	zval *group_name_obj;
	char group_name[FDFS_GROUP_NAME_MAX_LEN + 1];

    	argc = ZEND_NUM_ARGS();
	if (argc < 2 || argc > 4)
	{
		logError("file: "__FILE__", line: %d, " \
			"upload_file parameters count: %d < 2 or > 4", \
		__LINE__, argc);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	my_file_id = NULL;
	local_filename = NULL;
	filename_len = 0;
	ext_name_obj = NULL;
	group_name_obj = NULL;

	if (upload_type == FDFS_UPLOAD_BY_CALLBACK)
	{
		result = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, \
			"sa|zz", &my_file_id, &my_file_id_len, &callback_obj, \
			&ext_name_obj, &group_name_obj);
	}
	else
	{
		result = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, \
			"ss|zz", &my_file_id, &my_file_id_len, \
			&local_filename, &filename_len, \
			&ext_name_obj, &group_name_obj);
	}

	if (result == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"zend_parse_parameters fail!", __LINE__);
		pContext->err_no = EINVAL;
		RETURN_BOOL(false);
	}

	CHECK_MY_FILE_ID_LEN(pContext, my_file_id_len);

	if (ext_name_obj == NULL)
	{
		file_ext_name = NULL;
	}
	else
	{
		if (ext_name_obj->type == IS_NULL)
		{
			file_ext_name = NULL;
		}
		else if (ext_name_obj->type == IS_STRING)
		{
			file_ext_name = ext_name_obj->value.str.val;
		}
		else
		{
			logError("file: "__FILE__", line: %d, " \
				"file_ext_name is not a string, type=%d!", \
				__LINE__, ext_name_obj->type);
			pContext->err_no = EINVAL;
			RETURN_BOOL(false);
		}
	}

	if (group_name_obj != NULL && group_name_obj->type == IS_STRING)
	{
		snprintf(group_name, sizeof(group_name), "%s", \
			group_name_obj->value.str.val);
	}
	else
	{
		*group_name = '\0';
	}

	if (upload_type == FDFS_UPLOAD_BY_FILE)
	{
		pContext->err_no = my_fdfs_upload_by_filename_ex( \
			pContext->pMyClientContext, my_file_id, cmd, \
			local_filename, file_ext_name, group_name);
	}
	else if (upload_type == FDFS_UPLOAD_BY_BUFF)
	{
		char *buff;
		int buff_len;

		buff = local_filename;
		buff_len = filename_len;
		pContext->err_no = my_fdfs_do_upload_file( \
			pContext->pMyClientContext, my_file_id, \
			cmd, FDFS_UPLOAD_BY_BUFF, buff, NULL, \
			buff_len, file_ext_name, group_name);
	}
	else  //by callback
	{
		HashTable *callback_hash;
		php_fdfs_upload_callback_t php_callback;

		callback_hash = Z_ARRVAL_P(callback_obj);
		result = php_fdfs_get_upload_callback_from_hash(callback_hash, \
				&php_callback);
		if (result != 0)
		{
			pContext->err_no = result;
			RETURN_BOOL(false);
		}

		pContext->err_no = my_fdfs_upload_by_callback_ex( \
			pContext->pMyClientContext, my_file_id, cmd, \
			php_fdfs_upload_callback, (void *)&php_callback, \
			php_callback.file_size, file_ext_name, group_name);
	}

	if (pContext->err_no == 0)
	{
		RETURN_BOOL(true);
	}
	else
	{
		RETURN_BOOL(false);
	}
}

/*
string my_fastdfs_client_version()
return client library version
*/
ZEND_FUNCTION(my_fastdfs_client_version)
{
	char szVersion[16];
	int len;

	len = sprintf(szVersion, "%d.%02d", \
		g_fdfs_version.major, g_fdfs_version.minor);

	RETURN_STRINGL(szVersion, len, 1);
}

static void php_fdfs_close(php_fdfs_t *i_obj TSRMLS_DC)
{
	if (i_obj->context.pMyClientContext == NULL)
	{
		return;
	}

	if (i_obj->context.pMyClientContext != \
		i_obj->pConfigInfo->pMyClientContext)
	{
		tracker_close_all_connections_ex(&(i_obj->context. \
			pMyClientContext->fdfs.tracker_group));
                fdht_disconnect_all_servers(&(i_obj->context. \
			pMyClientContext->fdht.group_array));
	}
        else if (!i_obj->context.pMyClientContext->fdht.keep_alive)
        {
                fdht_disconnect_all_servers(&(i_obj->context. \
			pMyClientContext->fdht.group_array));
        }
}

/* constructor/destructor */
static void php_fdfs_destroy(php_fdfs_t *i_obj TSRMLS_DC)
{
	php_fdfs_close(i_obj TSRMLS_CC);
	if (i_obj->context.pMyClientContext != NULL && \
		i_obj->context.pMyClientContext != \
		i_obj->pConfigInfo->pMyClientContext)
	{
		my_client_destroy(i_obj->context.pMyClientContext);
		efree(i_obj->context.pMyClientContext);
		i_obj->context.pMyClientContext = NULL;
	}

	efree(i_obj);
}

ZEND_RSRC_DTOR_FUNC(php_fdfs_dtor)
{
	if (rsrc->ptr != NULL)
	{
		php_fdfs_t *i_obj = (php_fdfs_t *)rsrc->ptr;
		php_fdfs_destroy(i_obj TSRMLS_CC);
		rsrc->ptr = NULL;
	}
}

/* MyFastDFSClient::__construct([int config_index = 0, bool bMultiThread = false])
   Creates a MyFastDFSClient object */
static PHP_METHOD(MyFastDFSClient, __construct)
{
	long config_index;
	bool bMultiThread;
	zval *object = getThis();
	php_fdfs_t *i_obj;

	config_index = 0;
	bMultiThread = false;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|lb", \
			&config_index, &bMultiThread) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, " \
			"zend_parse_parameters fail!", __LINE__);
		ZVAL_NULL(object);
		return;
	}

	if (config_index < 0 || config_index >= config_count)
	{
		logError("file: "__FILE__", line: %d, " \
			"invalid config_index: %ld < 0 || >= %d", \
			__LINE__, config_index, config_count);
		ZVAL_NULL(object);
		return;
	}

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	i_obj->pConfigInfo = config_list + config_index;
	i_obj->context.err_no = 0;
	if (bMultiThread)
	{
		i_obj->context.pMyClientContext = (MyClientContext *)emalloc( \
					sizeof(MyClientContext));
		if (i_obj->context.pMyClientContext == NULL)
		{
			i_obj->context.err_no = errno != 0 ? errno : ENOMEM;
			logError("file: "__FILE__", line: %d, " \
				"malloc %d bytes fail!", __LINE__, \
				(int)sizeof(MyClientContext));
			ZVAL_NULL(object);
			return;
		}

		if ((i_obj->context.err_no=my_fdfs_copy_context( \
			i_obj->context.pMyClientContext, \
			i_obj->pConfigInfo->pMyClientContext)) != 0)
		{
			ZVAL_NULL(object);
			return;
		}
	}
	else
	{
		i_obj->context.pMyClientContext = i_obj->pConfigInfo->pMyClientContext;
	}
}

/*
array MyFastDFSClient::tracker_get_connection()
return array for success, false for error
*/
PHP_METHOD(MyFastDFSClient, tracker_get_connection)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	/*
	php_fdfs_tracker_get_connection_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
				&(i_obj->context));
	*/
}

/*
void MyFastDFSClient::close()
*/
PHP_METHOD(MyFastDFSClient, close)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_fdfs_close(i_obj TSRMLS_CC);
}

/*
string MyFastDFSClient::get_file_id(string my_file_id)
*/
PHP_METHOD(MyFastDFSClient, get_file_id)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_my_fdfs_get_file_id_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
                        &(i_obj->context));
}

/*
boolean MyFastDFSClient::upload_by_filename(string my_file_id, 
	string local_filename [, string file_ext_name, string group_name])
return true for success, false for error
*/
PHP_METHOD(MyFastDFSClient, upload_by_filename)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_my_fdfs_upload_file_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
		&(i_obj->context), STORAGE_PROTO_CMD_UPLOAD_FILE, \
		FDFS_UPLOAD_BY_FILE);
}

/*
boolean MyFastDFSClient::upload_by_filebuff(string my_file_id, string file_buff
	[, string file_ext_name, string group_name])
return true for success, false for error
*/
PHP_METHOD(MyFastDFSClient, upload_by_filebuff)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_my_fdfs_upload_file_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
		&(i_obj->context), STORAGE_PROTO_CMD_UPLOAD_FILE, \
		FDFS_UPLOAD_BY_BUFF);
}

/*
boolean MyFastDFSClient::upload_by_callback(string my_file_id, 
	array callback_array [, string file_ext_name, string group_name])
return true for success, false for error
*/
PHP_METHOD(MyFastDFSClient, upload_by_callback)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_my_fdfs_upload_file_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
		&(i_obj->context), STORAGE_PROTO_CMD_UPLOAD_FILE, \
		FDFS_UPLOAD_BY_CALLBACK);
}

/*
boolean MyFastDFSClient::upload_appender_by_filename(string my_file_id, 
	string local_filename [, string file_ext_name, string group_name])
return true for success, false for error
*/
PHP_METHOD(MyFastDFSClient, upload_appender_by_filename)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_my_fdfs_upload_file_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
		&(i_obj->context), STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE, \
		FDFS_UPLOAD_BY_FILE);
}

/*
boolean MyFastDFSClient::upload_appender_by_filebuff(string my_file_id, string file_buff
	[, string file_ext_name, string group_name])
return true for success, false for error
*/
PHP_METHOD(MyFastDFSClient, upload_appender_by_filebuff)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_my_fdfs_upload_file_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
		&(i_obj->context), STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE, \
		FDFS_UPLOAD_BY_BUFF);
}

/*
boolean MyFastDFSClient::upload_appender_by_callback(string my_file_id, 
	array callback_array [, string file_ext_name, string group_name])
return true for success, false for error
*/
PHP_METHOD(MyFastDFSClient, upload_appender_by_callback)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	php_my_fdfs_upload_file_impl(INTERNAL_FUNCTION_PARAM_PASSTHRU, \
		&(i_obj->context), STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE, \
		FDFS_UPLOAD_BY_CALLBACK);
}

/*
long MyFastDFSClient::get_last_error_no()
return last error no
*/
PHP_METHOD(MyFastDFSClient, get_last_error_no)
{
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	RETURN_LONG(i_obj->context.err_no);
}

/*
string MyFastDFSClient::get_last_error_info()
return last error info
*/
PHP_METHOD(MyFastDFSClient, get_last_error_info)
{
	char *error_info;
	zval *object = getThis();
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *) zend_object_store_get_object(object TSRMLS_CC);
	error_info = STRERROR(i_obj->context.err_no);
	RETURN_STRINGL(error_info, strlen(error_info), 1);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_close, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_get_last_error_no, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_get_last_error_info, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_get_file_id, 0, 0, 1)
ZEND_ARG_INFO(0, my_file_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_upload_by_filename, 0, 0, 2)
ZEND_ARG_INFO(0, my_file_id)
ZEND_ARG_INFO(0, local_filename)
ZEND_ARG_INFO(0, file_ext_name)
ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_upload_by_filebuff, 0, 0, 2)
ZEND_ARG_INFO(0, my_file_id)
ZEND_ARG_INFO(0, file_buff)
ZEND_ARG_INFO(0, file_ext_name)
ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_upload_by_callback, 0, 0, 2)
ZEND_ARG_INFO(0, my_file_id)
ZEND_ARG_INFO(0, callback_array)
ZEND_ARG_INFO(0, file_ext_name)
ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_upload_appender_by_filename, 0, 0, 2)
ZEND_ARG_INFO(0, my_file_id)
ZEND_ARG_INFO(0, local_filename)
ZEND_ARG_INFO(0, file_ext_name)
ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_upload_appender_by_filebuff, 0, 0, 2)
ZEND_ARG_INFO(0, my_file_id)
ZEND_ARG_INFO(0, file_buff)
ZEND_ARG_INFO(0, file_ext_name)
ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_upload_appender_by_callback, 0, 0, 2)
ZEND_ARG_INFO(0, my_file_id)
ZEND_ARG_INFO(0, callback_array)
ZEND_ARG_INFO(0, file_ext_name)
ZEND_ARG_INFO(0, group_name)
ZEND_END_ARG_INFO()

/* {{{ my_fdfs_class_methods */
#define MY_FDFS_ME(name, args) PHP_ME(MyFastDFSClient, name, args, ZEND_ACC_PUBLIC)
static zend_function_entry my_fdfs_class_methods[] = {
    MY_FDFS_ME(__construct,        arginfo___construct)
    MY_FDFS_ME(close,              arginfo_close)
    MY_FDFS_ME(get_last_error_no,  arginfo_get_last_error_no)
    MY_FDFS_ME(get_last_error_info,arginfo_get_last_error_info)
    MY_FDFS_ME(get_file_id,        arginfo_get_file_id)
    MY_FDFS_ME(upload_by_filename, arginfo_upload_by_filename)
    MY_FDFS_ME(upload_by_filebuff, arginfo_upload_by_filebuff)
    MY_FDFS_ME(upload_by_callback, arginfo_upload_by_callback)
    MY_FDFS_ME(upload_appender_by_filename, arginfo_upload_appender_by_filename)
    MY_FDFS_ME(upload_appender_by_filebuff, arginfo_upload_appender_by_filebuff)
    MY_FDFS_ME(upload_appender_by_callback, arginfo_upload_appender_by_callback)
    { NULL, NULL, NULL }
};
#undef MY_FDFS_ME
/* }}} */

static void php_fdfs_free_storage(php_fdfs_t *i_obj TSRMLS_DC)
{
	zend_object_std_dtor(&i_obj->zo TSRMLS_CC);
	php_fdfs_destroy(i_obj TSRMLS_CC);
}

zend_object_value php_fdfs_new(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	php_fdfs_t *i_obj;

	i_obj = (php_fdfs_t *)ecalloc(1, sizeof(php_fdfs_t));

	zend_object_std_init(&i_obj->zo, ce TSRMLS_CC);
	retval.handle = zend_objects_store_put(i_obj, \
		(zend_objects_store_dtor_t)zend_objects_destroy_object, \
		(zend_objects_free_object_storage_t)php_fdfs_free_storage, \
		NULL TSRMLS_CC);
	retval.handlers = zend_get_std_object_handlers();

	return retval;
}

PHP_MY_FASTDFS_API zend_class_entry *php_fdfs_get_ce(void)
{
	return fdfs_ce;
}

PHP_MY_FASTDFS_API zend_class_entry *php_fdfs_get_exception(void)
{
	return fdfs_exception_ce;
}

PHP_MY_FASTDFS_API zend_class_entry *php_fdfs_get_exception_base(int root TSRMLS_DC)
{
#if HAVE_SPL
	if (!root)
	{
		if (!spl_ce_RuntimeException)
		{
			zend_class_entry **pce;
			zend_class_entry ***ppce;

			ppce = &pce;
			if (zend_hash_find(CG(class_table), "runtimeexception",
			   sizeof("RuntimeException"), (void **) ppce) == SUCCESS)
			{
				spl_ce_RuntimeException = *pce;
				return *pce;
			}
		}
		else
		{
			return spl_ce_RuntimeException;
		}
	}
#endif
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 2)
	return zend_exception_get_default();
#else
	return zend_exception_get_default(TSRMLS_C);
#endif
}

static int load_cluster_item_value(const char *item_name_prefix, \
	const int index, zval *value)
{
	char szItemName[64];
	int nItemLen;

	nItemLen = sprintf(szItemName, "%s%d", item_name_prefix, index);
	if (zend_get_configuration_directive(szItemName, nItemLen + 1, \
		value) == SUCCESS)
	{
		return 0;
	}

	if (index != 0)
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"my_fastdfs_client.ini: get param %s " \
			"fail!\n", __LINE__, szItemName);

		return ENOENT;
	}

	if (zend_get_configuration_directive(item_name_prefix, \
		strlen(item_name_prefix) + 1, value) != SUCCESS)
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"my_fastdfs_client.ini: get param %s fail!\n", \
			__LINE__, item_name_prefix);

		return ENOENT;
	}

	return 0;
}

static int load_config_files()
{
	#define ITEM_NAME_CONF_COUNT      "my_fastdfs_client.cluster_count"
	#define ITEM_NAME_FDFS_CONF_FILE  "my_fastdfs_client.fdfs_config_filename"
	#define ITEM_NAME_FDHT_CONF_FILE  "my_fastdfs_client.fdht_config_filename"
	#define ITEM_NAME_FDHT_NAMESPACE  "my_fastdfs_client.fdht_namespace"
	#define ITEM_NAME_LOG_LEVEL       "my_fastdfs_client.log_level"
	#define ITEM_NAME_LOG_FILENAME    "my_fastdfs_client.log_filename"

	zval conf_c;
	zval log_level;
	zval log_filename;
	zval fdfs_conf_filename;
	zval fdht_conf_filename;
	zval fdht_namespace;
	FDFSConfigInfo *pConfigInfo;
	FDFSConfigInfo *pConfigEnd;
	int result;

	if (zend_get_configuration_directive(ITEM_NAME_CONF_COUNT, 
		sizeof(ITEM_NAME_CONF_COUNT), &conf_c) == SUCCESS)
	{
		config_count = atoi(conf_c.value.str.val);
		if (config_count <= 0)
		{
			fprintf(stderr, "file: "__FILE__", line: %d, " \
				"my_fastdfs_client.ini, %s: %d <= 0!\n", \
				__LINE__, ITEM_NAME_CONF_COUNT, config_count);
			return EINVAL;
		}
	}
	else
	{
		 config_count = 1;
	}

	if (zend_get_configuration_directive(ITEM_NAME_LOG_LEVEL, \
			sizeof(ITEM_NAME_LOG_LEVEL), \
			&log_level) == SUCCESS)
	{
		set_log_level(log_level.value.str.val);
	}

	if (zend_get_configuration_directive(ITEM_NAME_LOG_FILENAME, \
			sizeof(ITEM_NAME_LOG_FILENAME), \
			&log_filename) == SUCCESS)
	{
		if (log_filename.value.str.len > 0)
		{
			log_set_filename(log_filename.value.str.val);
		}
	}

	config_list = (FDFSConfigInfo *)malloc(sizeof(FDFSConfigInfo) * \
			config_count);
	if (config_list == NULL)
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"malloc %d bytes fail!\n",\
			__LINE__, (int)sizeof(FDFSConfigInfo) * config_count);
		return errno != 0 ? errno : ENOMEM;
	}

	pConfigEnd = config_list + config_count;
	for (pConfigInfo=config_list; pConfigInfo<pConfigEnd; pConfigInfo++)
	{
		int index = (int)(pConfigInfo - config_list);
		if ((result=load_cluster_item_value(ITEM_NAME_FDFS_CONF_FILE, \
			index, &fdfs_conf_filename)) != 0)
		{
			return result;
		}

		if ((result=load_cluster_item_value(ITEM_NAME_FDHT_CONF_FILE, \
			index, &fdht_conf_filename)) != 0)
		{
			return result;
		}

		if ((result=load_cluster_item_value(ITEM_NAME_FDHT_NAMESPACE, \
			index, &fdht_namespace)) != 0)
		{
			return result;
		}

		pConfigInfo->pMyClientContext = (MyClientContext *)malloc( \
						sizeof(MyClientContext));
		if (pConfigInfo->pMyClientContext == NULL)
		{
			fprintf(stderr, "file: "__FILE__", line: %d, " \
				"malloc %d bytes fail!\n", \
				__LINE__, (int)sizeof(MyClientContext));
			return errno != 0 ? errno : ENOMEM;
		}

		if ((result=my_client_init(pConfigInfo->pMyClientContext, \
				fdht_namespace.value.str.val, \
				fdfs_conf_filename.value.str.val, \
				fdht_conf_filename.value.str.val)) != 0)
		{
			return result;
		}
	}

	//logInfo("base_path=%s, cluster_count=%d", g_fdfs_base_path, config_count);
	return 0;
}

PHP_MINIT_FUNCTION(my_fastdfs_client)
{
	zend_class_entry ce;
	int le_my_fdfs;

	log_init();
	if (load_config_files() != 0)
	{
		return FAILURE;
	}

	le_my_fdfs = zend_register_list_destructors_ex(NULL, php_fdfs_dtor, \
			"MyFastDFSClient", module_number);

	INIT_CLASS_ENTRY(ce, "MyFastDFSClient", my_fdfs_class_methods);
	fdfs_ce = zend_register_internal_class(&ce TSRMLS_CC);
	fdfs_ce->create_object = php_fdfs_new;

	INIT_CLASS_ENTRY(ce, "MyFastDFSClientException", NULL);
	fdfs_exception_ce = zend_register_internal_class_ex(&ce, \
		php_fdfs_get_exception_base(0 TSRMLS_CC), NULL TSRMLS_CC);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(my_fastdfs_client)
{
	FDFSConfigInfo *pConfigInfo;
	FDFSConfigInfo *pConfigEnd;

	if (config_list != NULL)
	{
		pConfigEnd = config_list + config_count;
		for (pConfigInfo=config_list; pConfigInfo<pConfigEnd; \
			pConfigInfo++)
		{
			if (pConfigInfo->pMyClientContext == NULL)
			{
				continue;
			}
			my_client_destroy(pConfigInfo->pMyClientContext);
		}
	}

	log_destroy();

	return SUCCESS;
}

PHP_RINIT_FUNCTION(my_fastdfs_client)
{
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(my_fastdfs_client)
{
	//fprintf(stderr, "request shut down. file: "__FILE__", line: %d\n", __LINE__);
	return SUCCESS;
}

PHP_MINFO_FUNCTION(my_fastdfs_client)
{
	char fastdfs_info[64];
	sprintf(fastdfs_info, "my_fastdfs_client v%d.%02d support", 
		g_fdfs_version.major, g_fdfs_version.minor);

	php_info_print_table_start();
	php_info_print_table_header(2, fastdfs_info, "enabled");
	php_info_print_table_end();
}
