#include "my_fdfs_client.h"

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

