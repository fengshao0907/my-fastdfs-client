/**
* Copyright (C) 2012 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the Less GNU General
* Public License (LGPL), which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

#ifndef MY_FDFS_CLIENT_H
#define MY_FDFS_CLIENT_H

#include "tracker_types.h"
#include "tracker_proto.h"
#include "storage_client.h"
#include "my_fdfs_client.h"
#include "fdht_types.h"
#include "fdht_client.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MY_CLIENT_FILE_ID_KEY_NAME	"fdfs_fid"

typedef struct tagMyClientContext
{
	struct FastDFSContext {
		TrackerServerGroup tracker_group;
	} fdfs;

	struct FastDHTContext {
		int namespace_len;
		char szNameSpace[FDHT_MAX_NAMESPACE_LEN + 1];
		GroupArray group_array;
		bool keep_alive;
	} fdht;
} MyClientContext;

/*
client init function
param:
*	pContext : the context to be init
*       szFDHTNameSpace: the namespace of FastDHT to store FastDFS file id
*       fastdfs_conf_filename: FastDFS client config filename
*       fastdht_conf_filename: FastDHT client config filename
* return: 0 for success, != 0 for fail (errno)
*/
int my_client_init(MyClientContext *pContext, const char *szFDHTNameSpace, 
	const char *fastdfs_conf_filename, const char *fastdht_conf_filename);


/*
client destroy function
param:
*	pContext : the context to be detroy
*/
void my_client_destroy(MyClientContext *pContext);

/**
* get FastDFS file id
* params:
*	pContext: the context inited by my_client_init
*       my_file_id: the file id to get
*	fdfs_file_id: return the FastDFS file id
*	file_id_size: the buffer size of the FastDFS file id 
* return: 0 for success, != 0 for fail (errno)
**/
int my_fdfs_get_file_id(MyClientContext *pContext, const char *my_file_id, \
		char *fdfs_file_id, const int file_id_size);

/**
* upload file to storage server (by file name)
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to upload
*       local_filename: local filename to upload
*       file_ext_name: file ext name, not include dot(.), 
*                      if be NULL will abstract ext name from the local filename
*       group_name: specify the group name to upload file to, can be NULL or emtpy
* return: 0 success, !=0 fail, return the error code
**/
#define my_fdfs_upload_by_filename(pContext, local_filename, file_ext_name, \
		group_name, my_file_id) \
	my_fdfs_upload_by_filename_ex(pContext, my_file_id, \
		STORAGE_PROTO_CMD_UPLOAD_FILE, \
		local_filename, file_ext_name, group_name)

#define my_fdfs_upload_appender_by_filename(pContext, my_file_id, \
		local_filename, file_ext_name, group_name) \
	my_fdfs_upload_by_filename_ex(pContext, my_file_id, \
		STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE, \
		local_filename, file_ext_name, group_name)

int my_fdfs_upload_by_filename_ex(MyClientContext *pContext, \
		const char *my_file_id, const char cmd, \
		const char *local_filename, const char *file_ext_name, \
		const char *group_name);

/**
* upload file to storage server (by file buff)
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to upload
*       file_buff: file content/buff
*       file_size: file size (bytes)
*       file_ext_name: file ext name, not include dot(.), can be NULL
*       group_name: specify the group name to upload file to, can be NULL or emtpy
* return: 0 success, !=0 fail, return the error code
**/
#define my_fdfs_upload_by_filebuff(pContext, my_file_id, file_buff, \
		file_size, file_ext_name, group_name) \
	my_fdfs_do_upload_file(pContext, my_file_id, \
		STORAGE_PROTO_CMD_UPLOAD_FILE, \
		FDFS_UPLOAD_BY_BUFF, file_buff, NULL, \
		file_size, file_ext_name, group_name)

#define my_fdfs_upload_appender_by_filebuff(pContext, my_file_id, file_buff, \
		file_size, file_ext_name, group_name) \
	my_fdfs_do_upload_file(pContext, my_file_id, \
		STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE, \
		FDFS_UPLOAD_BY_BUFF, file_buff, NULL, \
		file_size, file_ext_name, group_name)

int my_fdfs_do_upload_file(MyClientContext *pContext, const char *my_file_id, \
	const char cmd, const int upload_type, const char *file_buff, \
	void *arg, const int64_t file_size, const char *file_ext_name, \
	const char *group_name);

/**
* upload file to storage server (by callback)
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to upload
*       file_size: the file size
*       file_ext_name: file ext name, not include dot(.), can be NULL
*       callback: callback function to send file content to storage server
*       arg: callback extra arguement
*       group_name: specify the group name to upload file to, can be NULL or emtpy
* return: 0 success, !=0 fail, return the error code
**/
#define my_fdfs_upload_by_callback(pContext, my_file_id, callback, arg, \
		file_size, file_ext_name, group_name) \
	my_fdfs_upload_by_callback_ex(pContext, my_file_id, \
		STORAGE_PROTO_CMD_UPLOAD_FILE, \
		callback, arg, file_size, file_ext_name, group_name)

#define my_fdfs_upload_appender_by_callback(pContext, my_file_id, \
		callback, arg, file_size, file_ext_name, group_name) \
	my_fdfs_upload_by_callback_ex(pContext, my_file_id, \
		STORAGE_PROTO_CMD_UPLOAD_APPENDER_FILE, \
		callback, arg, file_size, file_ext_name, group_name)

int my_fdfs_upload_by_callback_ex(MyClientContext *pContext, \
		const char *my_file_id, const char cmd, \
		UploadCallback callback, void *arg, \
		const int64_t file_size, const char *file_ext_name, \
		const char *group_name);

/**
* delete file from storage server
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to delete
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_delete_file(MyClientContext *pContext, const char *my_file_id);

/**
* download file from storage server
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to download
*       file_buff: return file content/buff, must be freed
*       file_size: return file size (bytes)
* return: 0 success, !=0 fail, return the error code
**/
#define my_fdfs_download_file(pContext, my_file_id, file_buff, file_size) \
	my_fdfs_do_download_file_ex(pContext, FDFS_DOWNLOAD_TO_BUFF, \
			my_file_id, 0, 0, file_buff, NULL, file_size)

#define my_fdfs_download_file_to_buff(pContext, my_file_id, file_buff, file_size) \
	my_fdfs_do_download_file_ex(pContext, FDFS_DOWNLOAD_TO_BUFF, \
			my_file_id, 0, 0, file_buff, NULL, file_size)

#define my_fdfs_do_download_file(pContext, download_type, my_file_id, \
		file_buff, file_size) \
	my_fdfs_do_download_file_ex(pContext, download_type, my_file_id, \
			0, 0, file_buff, NULL, file_size)

/**
* download file from storage server
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to download
*       file_offset: the start offset to download
*       download_bytes: download bytes, 0 means from start offset to the file end
*       file_buff: return file content/buff, must be freed
*       file_size: return file size (bytes)
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_do_download_file_ex(MyClientContext *pContext, \
		const int download_type, const char *my_file_id, \
		const int64_t file_offset, const int64_t download_bytes, \
		char **file_buff, void *arg, int64_t *file_size);

/**
* download file from storage server
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to download
*	local_filename: local filename to write
*       file_size: return file size (bytes)
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_download_file_to_file(MyClientContext *pContext, \
		const char *my_file_id, const char *local_filename, \
		int64_t *file_size);


/**
* download file from storage server
* params:
*	pContext: the context inited by my_client_init
*	my_file_id: the file id to download
*       file_offset: the start offset to download
*       download_bytes: download bytes, 0 means from start offset to the file end
*	callback: callback function
*	arg: callback extra arguement
*       file_size: return file size (bytes)
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_download_file_ex(MyClientContext *pContext, const char *my_file_id, \
		const int64_t file_offset, const int64_t download_bytes, \
		DownloadCallback callback, void *arg, int64_t *file_size);


/**
* append file to storage server (by filename)
* params:
*	pContext: the context inited by my_client_init
*       my_appender_file_id: the appender file id
*       local_filename: local filename to upload
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_append_by_filename(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		const char *local_filename);


/**
* append file to storage server (by file buff)
* params:
*	pContext: the context inited by my_client_init
*       my_appender_file_id: the appender file id
*       file_buff: file content/buff
*       file_size: file size (bytes)
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_append_by_filebuff(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		const char *file_buff, const int64_t file_size);


/**
* append file to storage server (by callback)
* params:
*	pContext: the context inited by my_client_init
*       my_appender_file_id: the appender file id
*       callback: callback function to send file content to storage server
*       arg: callback extra arguement
*       file_size: the file size
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_append_by_callback(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		UploadCallback callback, void *arg, const int64_t file_size);


/**
* modify file to storage server (by local filename)
* params:
*	pContext: the context inited by my_client_init
*       my_appender_file_id: the appender file id
*       local_filename: local filename to upload
*       file_offset: the start offset to modify appender file
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_modify_by_filename(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		const char *local_filename, const int64_t file_offset);



/**
* modify file to storage server (by file buff)
* params:
*	pContext: the context inited by my_client_init
*       my_appender_file_id: the appender file id
*       file_buff: file content/buff
*       file_offset: the start offset to modify appender file
*       file_size: file size (bytes)
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_modify_by_filebuff(MyClientContext *pContext, \
		const char *my_appender_file_id, const char *file_buff, \
		const int64_t file_offset, const int64_t file_size);


/**
* modify file to storage server (by callback)
* params:
*	pContext: the context inited by my_client_init
*       my_appender_file_id: the appender file id
*       callback: callback function to send file content to storage server
*       arg: callback extra arguement
*       file_offset: the start offset to modify appender file
*       file_size: the file size
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_modify_by_callback(MyClientContext *pContext, \
		const char *my_appender_file_id, \
		UploadCallback callback, void *arg, \
		const int64_t file_offset, const int64_t file_size);


/**
* delete file from storage server
* params:
*	pContext: the context inited by my_client_init
*       my_appender_file_id: the appender file id
*	truncated_file_size: the truncated file size
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_truncate_file(MyClientContext *pContext, \
	const char *my_appender_file_id, const int64_t truncated_file_size);


#define my_fdfs_query_file_info(pContext, my_file_id, pFileInfo) \
	my_fdfs_query_file_info_ex(pContext, my_file_id, pFileInfo, false)

/**
* query file info
* params:
*	pContext: the context inited by my_client_init
*       my_file_id: the file id
*	pFileInfo: return the file info (file size and create timestamp)
*	bSilence: when this file not exist, do not log error on storage server
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_query_file_info_ex(MyClientContext *pContext, \
		const char *my_file_id, FDFSFileInfo *pFileInfo, \
		const bool bSilence);

#define my_fdfs_get_file_info(pContext, my_file_id, pFileInfo) \
	my_fdfs_get_file_info_ex(pContext, my_file_id, true, pFileInfo)

/**
* get file info from the filename return by storage server
* params:
*	pContext: the context inited by my_client_init
*       my_file_id: the file id
*       get_from_server: if get file info from storage server
*       pFileInfo: return the file info
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_get_file_info_ex(MyClientContext *pContext, \
		const char *my_file_id, const bool get_from_server, \
		FDFSFileInfo *pFileInfo);

/**
* check if file exist
* params:
*	pContext: the context inited by my_client_init
*       my_file_id: the file id to check
* return: 0 file exist, !=0 not exist, return the error code
**/
int my_fdfs_file_exist(MyClientContext *pContext, const char *my_file_id);


/**
* copy context
* params:
*	pDestContext: the dest context
*	pSrcContext: the source context
* return: 0 success, !=0 fail, return the error code
**/
int my_fdfs_copy_context(MyClientContext *pDestContext, \
	MyClientContext *pSrcContext);

#ifdef __cplusplus
}
#endif

#endif

