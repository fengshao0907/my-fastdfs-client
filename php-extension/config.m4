dnl config.m4 for extension my_fastdfs_client

PHP_ARG_WITH(my_fastdfs_client, for my_fastdfs_client support my FastDFS client,
[  --with-my_fastdfs_client             Include my_fastdfs_client support my FastDFS client])

if test "$PHP_MY_FASTDFS_CLIENT" != "no"; then
  PHP_SUBST(MY_FASTDFS_CLIENT_SHARED_LIBADD)

  if test -z "$ROOT"; then
	ROOT=/usr/local
  fi

  PHP_ADD_INCLUDE($ROOT/include/fastcommon)
  PHP_ADD_INCLUDE($ROOT/include/fastdfs)
  PHP_ADD_INCLUDE($ROOT/include/fastdht)

  PHP_ADD_LIBRARY_WITH_PATH(fastcommon, $ROOT/lib, MY_FASTDFS_CLIENT_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(fdfsclient, $ROOT/lib, MY_FASTDFS_CLIENT_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(fdhtclient, $ROOT/lib, MY_FASTDFS_CLIENT_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(myfdfsclient, $ROOT/lib, MY_FASTDFS_CLIENT_SHARED_LIBADD)

  PHP_NEW_EXTENSION(my_fastdfs_client, php_my_fastdfs_client.c, $ext_shared)

  CFLAGS="$CFLAGS -Werror -Wall"
fi
