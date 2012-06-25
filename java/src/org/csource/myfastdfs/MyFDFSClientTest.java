/** Copyright (C) 2012 Happy Fish / YuQing
 *  My FastDFS Java Client may be copied only under the terms of the GNU Lesser
 * General Public License (LGPL). 
 * Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
 */

package org.csource.myfastdfs;

import java.io.FileNotFoundException;
import java.io.IOException;
import org.csource.common.MyException;

/** My FastDFS test
* @author Happy Fish / YuQing
* @version Version 1.00
*/
public class MyFDFSClientTest
{	
	public MyFDFSClientTest()
	{
	}

	public static void main(String[] args)
	{
		final String fdfsConfigFilename = "fdfs_client.conf";
		final String fdhtConfigFilename = "fdht_client.conf";
		final String fdhtNamespace = "fdfs";
		
		try
		{
			MyFastDFSClient.init(fdfsConfigFilename, fdhtConfigFilename);
			MyFastDFSClient myFDFSClient = new MyFastDFSClient(fdhtNamespace);
			
			final String my_file_id = "/aa/bb/11";
			final String local_filename = "c:\\windows\\system32\\notepad.exe";
			final String file_ext_name = "";
			int result;
			if ((result=myFDFSClient.upload_file(my_file_id, local_filename, file_ext_name)) != 0)
			{
				System.err.println("upload_file fail, errno: " + result);
				return;
			}
			
			System.out.println("fdfs_file_id: " + myFDFSClient.get_fdfs_file_id(my_file_id));
			
			if ((result=myFDFSClient.download_file(my_file_id, "c:\\my_fdfs_test.ext")) != 0)
			{
				System.err.println("download_file fail, errno: " + result);
				return;
			}
			
			System.out.println("delete_file result: " + myFDFSClient.delete_file(my_file_id));
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
	}
}
