#include "logger.h"
#include "my_fdfs_client.h"

int main(int argc, char **argv)
{
	MyClientContext context;
	const char *fastdht_namespace = "fdfs";
	const char *fastdfs_conf_filename = "/etc/fdfs/client.conf";
	const char *fastdht_conf_filename = "/etc/fdht/fdht_client.conf";
	int result;
	const char *local_filename = "/usr/include/stdio.h";
	const char *file_ext_name = NULL;
	const char *group_name = "";
	char my_file_id[128];
	char fdfs_file_id[128];
	int64_t file_size;

	log_init();
	//g_log_context.log_level = LOG_DEBUG;

	if ((result=my_client_init(&context, fastdht_namespace, 
		fastdfs_conf_filename, fastdht_conf_filename)) != 0)
	{
		return result;
	}

	strcpy(my_file_id, "fdfs/test/1");
	do
	{
		result = my_fdfs_upload_by_filename(&context, local_filename, 
			file_ext_name, group_name, my_file_id);
		if (result != 0)
		{
			fprintf(stderr, "upload file fail, errno: %d, " \
				"error info: %s\n", result, strerror(result));
			break;
		}

		result = my_fdfs_get_file_id(&context, my_file_id, 
			fdfs_file_id, sizeof(fdfs_file_id));
		if (result != 0)
		{
			fprintf(stderr, "get file id fail, errno: %d, " \
				"error info: %s\n", result, strerror(result));
			break;
		}
		printf("fdfs_file_id: %s\n", fdfs_file_id);

		result = my_fdfs_download_file_to_file(&context, my_file_id, 
			"./my_fdfs_test.tmp", &file_size);
		if (result != 0)
		{
			fprintf(stderr, "download file fail, errno: %d, " \
				"error info: %s\n", result, strerror(result));
			break;
		}

		result = my_fdfs_delete_file(&context, my_file_id);
		if (result != 0)
		{
			fprintf(stderr, "delete file fail, errno: %d, " \
				"error info: %s\n", result, strerror(result));
			break;
		}

		result = my_fdfs_get_file_id(&context, my_file_id, 
			fdfs_file_id, sizeof(fdfs_file_id));
		if (result == 0)
		{
			printf("oh, no!\n");
		}
		else if (result != ENOENT)
		{
			printf("my_fdfs_get_file_id fail, " \
				"errno: %d, error info: %s\n", \
				result, strerror(result));
		}
		result = 0;
	} while(0);

	my_client_destroy(&context);
	return result;
}

