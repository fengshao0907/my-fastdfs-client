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
	if ($file_buff=$myFastDFS->download_file_to_buff($my_file_id))
	{
		echo 'download file size: ' . strlen($file_buff) . "\n";
	}
	echo 'file_exists: ' . $myFastDFS->file_exists($my_file_id) . "\n";
	echo 'delete_file: ' . $myFastDFS->delete_file($my_file_id) . "\n";
?>
