<?php
	echo my_fastdfs_client_version() . "\n";

	$my_file_id = '12345678';
	$local_filename = "/usr/include/stdlib.h";
	$myFastDFS = new MyFastDFSClient();
	if (!$myFastDFS->upload_by_filename($my_file_id, $local_filename))
	{
		echo 'upload_by_filename fail, errno: ' . $myFastDFS->get_last_error_no()
			 . ', error info: ' . $myFastDFS->get_last_error_info() . "\n";
		exit;
	}

	echo 'fdfs_file_id: ' . $myFastDFS->get_file_id($my_file_id) . "\n";
?>
