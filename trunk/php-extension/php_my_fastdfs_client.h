#ifndef PHP_MY_FASTDFS_CLIENT_H
#define PHP_MY_FASTDFS_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PHP_WIN32
#define PHP_MY_FASTDFS_API __declspec(dllexport)
#else
#define PHP_MY_FASTDFS_API
#endif

PHP_MINIT_FUNCTION(my_fastdfs_client);
PHP_RINIT_FUNCTION(my_fastdfs_client);
PHP_MSHUTDOWN_FUNCTION(my_fastdfs_client);
PHP_RSHUTDOWN_FUNCTION(my_fastdfs_client);
PHP_MINFO_FUNCTION(my_fastdfs_client);

ZEND_FUNCTION(my_fastdfs_client_version);

PHP_MY_FASTDFS_API zend_class_entry *php_fdfs_get_ce(void);
PHP_MY_FASTDFS_API zend_class_entry *php_fdfs_get_exception(void);
PHP_MY_FASTDFS_API zend_class_entry *php_fdfs_get_exception_base(int root TSRMLS_DC);

#ifdef __cplusplus
}
#endif

#endif	/* MY_FASTDFS_CLIENT_H */
