/** Copyright (C) 2012 Happy Fish / YuQing
 *  My FastDFS Java Client may be copied only under the terms of the GNU Lesser
 * General Public License (LGPL). 
 * Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
 */

package org.csource.myfastdfs;

import java.io.FileNotFoundException;
import java.io.IOException;
import org.csource.common.MyException;
import org.csource.fastdfs.TrackerServer;
import org.csource.fastdfs.StorageServer;
import org.csource.fastdfs.UploadCallback;
import org.csource.fastdfs.DownloadCallback;
import org.csource.fastdfs.FileInfo;
import org.csource.fastdfs.StorageClient1;
import org.csource.fastdht.ServerGroup;
import org.csource.fastdht.FastDHTClient;
import org.csource.fastdht.KeyInfo;

/** My FastDFS client
* @author Happy Fish / YuQing
* @version Version 1.00
*/
public class MyFastDFSClient
{
	public static final String MY_CLIENT_FILE_ID_KEY_NAME = "fdfs_fid";

	protected StorageClient1 storageClient1;
	protected FastDHTClient fdhtClient;
	protected String fdhtNamespace;
	protected int status; //last error code
	
	/**
	* constructor
	* @param fdhtNamespace the FastDHT namespace
	*/
	public MyFastDFSClient(String fdhtNamespace) throws MyException
	{
		this.storageClient1 = new StorageClient1();
		this.fdhtClient = new FastDHTClient(true);
		if (fdhtNamespace == null || fdhtNamespace.length() == 0)
		{
			throw new MyException("FastDHT namespace must be set!");
		}
		this.fdhtNamespace = fdhtNamespace;
	}

	/**
	* constructor
	* @param trackerServer the FastDFS tracker server, can be null
	* @param storageServer the FastDFS storage server, can be null
	* @param serverGroup the FastDHT group info
	* @param fdhtNamespace the FastDHT namespace
	*/
	public MyFastDFSClient(TrackerServer trackerServer, StorageServer storageServer, ServerGroup serverGroup, String fdhtNamespace) throws MyException
	{
		this.storageClient1 = new StorageClient1(trackerServer, storageServer);
		this.fdhtClient = new FastDHTClient(serverGroup);
		if (fdhtNamespace == null || fdhtNamespace.length() == 0)
		{
			throw new MyException("FastDHT namespace must be set!");
		}
		this.fdhtNamespace = fdhtNamespace;
	}
	
	/**
	* load parameters from FastDFS and FastDHT config file
	* @param fdfsConfigFilename the FastDFS config filename
	* @param fdhtConfigFilename the FastDHT config filename
	*/
	public static void init(String fdfsConfigFilename, String fdhtConfigFilename) throws FileNotFoundException, IOException, MyException
	{
		org.csource.fastdfs.ClientGlobal.init(fdfsConfigFilename);
		org.csource.fastdht.ClientGlobal.init(fdhtConfigFilename);
	}

/**
* @return the error code of last call
*/
	public int getErrorCode()
	{
		return this.status;
	}

	/**
	* close connections
	*/
	public void close()
	{
		this.fdhtClient.close();
	}

	/**
	* check FastDFS file id not exist
  * @param keyInfo the FastDHT key object
	* @return true for not exist, otherwise false
	*/
	protected boolean check_fdfs_file_id_not_exist(KeyInfo keyInfo) throws IOException, MyException
	{
		String fdfs_file_id = this.fdhtClient.get(keyInfo);
		this.status = this.fdhtClient.getErrorCode();
		if (fdfs_file_id != null || this.status == 0)
		{
			this.status = 17;  //EEXIST
			throw new MyException("file id: " + new String(keyInfo.getObjectId(), org.csource.fastdht.ClientGlobal.g_charset) + " already exist");
		}
		
		return (this.status == 2);
	}

	/**
	* save FastDFS file id to FastDHT
  * @param keyInfo the FastDHT key object
  * @param fdfs_file_id the FastDFS file id
	* @return 0 for success, != 0 for error (error no)
	*/
	protected int set_fdfs_file_id(KeyInfo keyInfo, String fdfs_file_id) throws IOException, MyException
	{
		try
		{
			if ((this.status=this.fdhtClient.set(keyInfo, fdfs_file_id)) != 0)
			{
				this.storageClient1.delete_file1(fdfs_file_id);  //rollback
			}
		}
		catch(Exception ex)
		{
			this.status = 5;
			ex.printStackTrace();
			this.storageClient1.delete_file1(fdfs_file_id);  //rollback
		}
		
		return this.status;
	}

	/**
	* get FastDFS file id
  * @param my_file_id the file id specified by application
	* @return FastDFS file id for success, return null for fail
	*/
	public String get_fdfs_file_id(String my_file_id) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_file_id, MY_CLIENT_FILE_ID_KEY_NAME);
		String fdfs_file_id = this.fdhtClient.get(keyInfo);
		this.status = this.fdhtClient.getErrorCode();
		return fdfs_file_id;
	}
	
	/**
	* upload file to storage server (by file name)
  * @param my_file_id the file id specified by application
	* @param local_filename local filename to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_file(String my_file_id, String local_filename, String file_ext_name) throws IOException, MyException
	{
		final String group_name = "";
		return this.upload_file(my_file_id, group_name, local_filename, file_ext_name);
	}

	/**
	* upload file to storage server (by file name)
  * @param my_file_id the file id specified by application
	* @param group_name the group name to upload file to, can be empty
	* @param local_filename local filename to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_file(String my_file_id, String group_name, String local_filename, String file_ext_name) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_file_id, MY_CLIENT_FILE_ID_KEY_NAME);
		if (!this.check_fdfs_file_id_not_exist(keyInfo))
		{
			return this.status;
		}
		
		String fdfs_file_id = this.storageClient1.upload_file1(group_name, local_filename, file_ext_name, null);
		this.status = this.storageClient1.getErrorCode();
		if (fdfs_file_id == null)
		{
			return this.status;
		}
		
		return this.set_fdfs_file_id(keyInfo, fdfs_file_id);
	}

	/**
	* upload file to storage server (by file buffer)
  * @param my_file_id the file id specified by application
	* @param file_buff the file content / buffer to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_file(String my_file_id, byte[] file_buff, String file_ext_name) throws IOException, MyException
	{
		final String group_name = "";
		return this.upload_file(my_file_id, group_name, file_buff, file_ext_name);
	}
	
	/**
	* upload file to storage server (by file buffer)
  * @param my_file_id the file id specified by application
	* @param group_name the group name to upload file to, can be empty
	* @param file_buff the file content / buffer to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_file(String my_file_id, String group_name, byte[] file_buff, String file_ext_name) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_file_id, MY_CLIENT_FILE_ID_KEY_NAME);
		if (!this.check_fdfs_file_id_not_exist(keyInfo))
		{
			return this.status;
		}
		
		String fdfs_file_id = this.storageClient1.upload_file1(group_name, file_buff, file_ext_name, null);
		this.status = this.storageClient1.getErrorCode();
		if (fdfs_file_id == null)
		{
			return this.status;
		}
		
		return this.set_fdfs_file_id(keyInfo, fdfs_file_id);
	}
	
	/**
	* upload file to storage server (by callback object)
  * @param my_file_id the file id specified by application
	* @param file_size the file size
	* @param callback the write data callback object
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_file(String my_file_id, long file_size, 
	       UploadCallback callback, String file_ext_name) throws IOException, MyException
	{
		final String group_name = "";
		return this.upload_file(my_file_id, group_name, file_size, callback, file_ext_name);
	}
	
	/**
	* upload file to storage server (by callback object)
  * @param my_file_id the file id specified by application
	* @param group_name the group name to upload file to, can be empty
	* @param file_size the file size
	* @param callback the write data callback object
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_file(String my_file_id, String group_name, long file_size, 
	       UploadCallback callback, String file_ext_name) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_file_id, MY_CLIENT_FILE_ID_KEY_NAME);
		if (!this.check_fdfs_file_id_not_exist(keyInfo))
		{
			return this.status;
		}
		
		String fdfs_file_id = this.storageClient1.upload_file1(group_name, file_size, callback, file_ext_name, null);
		this.status = this.storageClient1.getErrorCode();
		if (fdfs_file_id == null)
		{
			return this.status;
		}
		
		return this.set_fdfs_file_id(keyInfo, fdfs_file_id);
	}

	/**
	* upload appender file to storage server (by file name)
  * @param my_appender_id the appender file id specified by application
	* @param local_filename local filename to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_appender_file(String my_appender_id, 
		String local_filename, String file_ext_name) throws IOException, MyException
	{
		final String group_name = "";
		return this.upload_appender_file(my_appender_id, group_name, local_filename, file_ext_name);
	}

	/**
	* upload appender file to storage server (by file name)
  * @param my_appender_id the appender file id specified by application
	* @param group_name the group name to upload appender file to, can be empty
	* @param local_filename local filename to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_appender_file(String my_appender_id, 
		String group_name, String local_filename, String file_ext_name) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_appender_id, MY_CLIENT_FILE_ID_KEY_NAME);
		if (!this.check_fdfs_file_id_not_exist(keyInfo))
		{
			return this.status;
		}
		
		String fdfs_file_id = this.storageClient1.upload_appender_file1(group_name, local_filename, file_ext_name, null);
		this.status = this.storageClient1.getErrorCode();
		if (fdfs_file_id == null)
		{
			return this.status;
		}
		
		return this.set_fdfs_file_id(keyInfo, fdfs_file_id);
	}

	/**
	* upload appender file to storage server (by file buffer)
  * @param my_appender_id the appender file id specified by application
	* @param file_buff the file content / buffer to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_appender_file(String my_appender_id, byte[] file_buff, 
		String file_ext_name) throws IOException, MyException
	{
		final String group_name = "";
		return this.upload_appender_file(my_appender_id, group_name, file_buff, file_ext_name);
	}
	
	/**
	* upload appender file to storage server (by file buffer)
  * @param my_appender_id the appender file id specified by application
	* @param group_name the group name to upload appender file to, can be empty
	* @param file_buff the file content / buffer to upload
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_appender_file(String my_appender_id, String group_name, 
		byte[] file_buff, String file_ext_name) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_appender_id, MY_CLIENT_FILE_ID_KEY_NAME);
		if (!this.check_fdfs_file_id_not_exist(keyInfo))
		{
			return this.status;
		}
		
		String fdfs_file_id = this.storageClient1.upload_appender_file1(group_name, file_buff, file_ext_name, null);
		this.status = this.storageClient1.getErrorCode();
		if (fdfs_file_id == null)
		{
			return this.status;
		}
		
		return this.set_fdfs_file_id(keyInfo, fdfs_file_id);
	}
		
	/**
	* upload appender file to storage server (by callback object)
  * @param my_appender_id the appender file id specified by application
	* @param file_size the file size
	* @param callback the write data callback object
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_appender_file(String my_appender_id, long file_size, 
	       UploadCallback callback, String file_ext_name) throws IOException, MyException
	{
		final String group_name = "";
		return this.upload_appender_file(my_appender_id, group_name, file_size, callback, file_ext_name);
	}
	
	/**
	* upload appender file to storage server (by callback object)
  * @param my_appender_id the appender file id specified by application
	* @param group_name the group name to upload appender file to, can be empty
	* @param file_size the file size
	* @param callback the write data callback object
	* @param file_ext_name file ext name, do not include dot(.), null to extract ext name from the local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int upload_appender_file(String my_appender_id, String group_name, 
		long file_size, UploadCallback callback, String file_ext_name) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_appender_id, MY_CLIENT_FILE_ID_KEY_NAME);
		if (!this.check_fdfs_file_id_not_exist(keyInfo))
		{
			return this.status;
		}
		
		String fdfs_file_id = this.storageClient1.upload_appender_file1(group_name, file_size, callback, file_ext_name, null);
		this.status = this.storageClient1.getErrorCode();
		if (fdfs_file_id == null)
		{
			return this.status;
		}
		
		return this.set_fdfs_file_id(keyInfo, fdfs_file_id);
	}
	
	/**
	* append file content to appender file (by file name)
  * @param my_appender_id the file id specified by application
	* @param local_filename local filename to append
	* @return 0 for success, != 0 for error (error no)
	*/
	public int append_file(String my_appender_id, String local_filename) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.append_file1(fdfs_appender_id, local_filename);
		}
		
		return this.status;
	}
	
	/**
	* append file content to appender file (by file buffer)
  * @param my_appender_id the file id specified by application
	* @param file_buff the file content / buffer to append
	* @return 0 for success, != 0 for error (error no)
	*/
	public int append_file(String my_appender_id, byte[] file_buff) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.append_file1(fdfs_appender_id, file_buff);
		}
		
		return this.status;
	}
	
	/**
	* append file content to appender file (by file buffer)
  * @param my_appender_id the file id specified by application
	* @param file_buff the file content / buffer to append
	* @param offset start offset of the buffer
	* @param length the length of the buffer to append
	* @return 0 for success, != 0 for error (error no)
	*/
	public int append_file(String my_appender_id, byte[] file_buff, int offset, int length) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.append_file1(fdfs_appender_id, file_buff, offset, length);
		}
		
		return this.status;
	}
	
	/**
	* append file content to appender file (by callback object)
  * @param my_appender_id the file id specified by application
	* @param file_size the file size
	* @param callback the write data callback object
	* @return 0 for success, != 0 for error (error no)
	*/
	public int append_file(String my_appender_id, long file_size, 
	       UploadCallback callback) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.append_file1(fdfs_appender_id, file_size, callback);
		}
		
		return this.status;
	}

	/**
	* modify appender file (by file name)
  * @param my_appender_id the file id specified by application
	* @param local_filename local filename
	* @return 0 for success, != 0 for error (error no)
	*/
	public int modify_file(String my_appender_id, long file_offset, String local_filename) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.modify_file1(fdfs_appender_id, file_offset, local_filename);
		}
		
		return this.status;
	}
	
	/**
	* modify appender file (by file buffer)
  * @param my_appender_id the file id specified by application
	* @param file_buff the file content / buffer
	* @return 0 for success, != 0 for error (error no)
	*/
	public int modify_file(String my_appender_id, long file_offset, byte[] file_buff) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.modify_file1(fdfs_appender_id, 
						file_offset, file_buff);
		}
		
		return this.status;
	}
	
	/**
	* modify appender file (by file buffer)
  * @param my_appender_id the file id specified by application
	* @param file_buff the file content / buffer
	* @param offset start offset of the buffer
	* @param length the length of the buffer
	* @return 0 for success, != 0 for error (error no)
	*/
	public int modify_file(String my_appender_id, long file_offset, byte[] file_buff, int offset, int length) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.modify_file1(fdfs_appender_id, 
						file_offset, file_buff, offset, length);
		}
		
		return this.status;
	}
	
	/**
	* modify appender file (by callback object)
  * @param my_appender_id the file id specified by application
  * @param file_offset the offset of appender file
	* @param modify_size the modified / content size
	* @param callback the write data callback object
	* @return 0 for success, != 0 for error (error no)
	*/
	public int modify_file(String my_appender_id, long file_offset, long modify_size, 
	       UploadCallback callback) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.modify_file1(fdfs_appender_id, 
						file_offset, modify_size, callback);
		}
		
		return this.status;
	}
	
	/**
	* delete file from storage server
  * @param my_file_id the file id specified by application
	* @return 0 for success, != 0 for error (error no)
	*/
	public int delete_file(String my_file_id) throws IOException, MyException
	{
		KeyInfo keyInfo = new KeyInfo(this.fdhtNamespace, my_file_id, MY_CLIENT_FILE_ID_KEY_NAME);
		String fdfs_file_id = this.fdhtClient.get(keyInfo);
		if (fdfs_file_id == null)
		{
			this.status = this.fdhtClient.getErrorCode();
			return this.status;
		}
		
		this.status = this.storageClient1.delete_file1(fdfs_file_id);
		if (this.status != 0)
		{
			return this.status;
		}
		
		this.status = this.fdhtClient.delete(keyInfo);
		return this.status;
	}
	
	/**
	* truncate appender file to size 0 from storage server
  * @param my_appender_id the file id specified by application
	* @return 0 for success, != 0 for error (error no)
	*/
	public int truncate_file(String my_appender_id) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.truncate_file1(fdfs_appender_id);
		}
		
		return this.status;
	}
	
	/**
	* truncate appender file from storage server
  * @param my_appender_id the file id specified by application
  * @param truncated_file_size truncated file size
	* @return 0 for success, != 0 for error (error no)
	*/
	public int truncate_file(String my_appender_id, long truncated_file_size) throws IOException, MyException
	{
		String fdfs_appender_id = this.get_fdfs_file_id(my_appender_id);
		if (fdfs_appender_id != null)
		{
			this.status = this.storageClient1.truncate_file1(fdfs_appender_id, truncated_file_size);
		}
		
		return this.status;
	}
	
	/**
	* download file from storage server
  * @param my_file_id the file id specified by application
	* @return file content/buffer, return null if fail
	*/
	public byte[] download_file(String my_file_id) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id == null)
		{
			return null;
		}
		
		byte[] bsResult = this.storageClient1.download_file1(fdfs_file_id);
		this.status = this.storageClient1.getErrorCode();
		return bsResult;
	}
	
	/**
	* download file from storage server
  * @param my_file_id the file id specified by application
	* @param file_offset the start offset of the file
	* @param download_bytes download bytes, 0 for remain bytes from offset
	* @return file content/buffer, return null if fail
	*/
	public byte[] download_file(String my_file_id, long file_offset, long download_bytes) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id == null)
		{
			return null;
		}
		
		byte[] bsResult = this.storageClient1.download_file1(fdfs_file_id, file_offset, download_bytes);
		this.status = this.storageClient1.getErrorCode();
		return bsResult;
	}
	
	/**
	* download file from storage server
  * @param my_file_id the file id specified by application
  * @param local_filename  the filename on local
	* @return 0 success, return none zero errno if fail
	*/
	public int download_file(String my_file_id, String local_filename) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id != null)
		{
			this.status = this.storageClient1.download_file1(fdfs_file_id, local_filename);
		}
		
		return this.status;
	}
	
	/**
	* download file from storage server
  * @param my_file_id the file id specified by application
	* @param file_offset the start offset of the file
	* @param download_bytes download bytes, 0 for remain bytes from offset
  * @param local_filename  the filename on local
	* @return 0 success, return none zero errno if fail
	*/
	public int download_file(String my_file_id, long file_offset, long download_bytes, String local_filename) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id != null)
		{
			this.status = this.storageClient1.download_file1(fdfs_file_id, file_offset, download_bytes, local_filename);
		}
		
		return this.status;
	}
	
	/**
	* download file from storage server
  * @param my_file_id the file id specified by application
  * @param callback the callback object, will call callback.recv() when data arrive
	* @return 0 success, return none zero errno if fail
	*/
	public int download_file(String my_file_id, DownloadCallback callback) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id != null)
		{
			this.status = this.storageClient1.download_file1(fdfs_file_id, callback);
		}
		
		return this.status;
	}
	
	/**
	* download file from storage server
  * @param my_file_id the file id specified by application
	* @param file_offset the start offset of the file
	* @param download_bytes download bytes, 0 for remain bytes from offset
  * @param callback the callback object, will call callback.recv() when data arrive
	* @return 0 success, return none zero errno if fail
	*/
	public int download_file(String my_file_id, long file_offset, long download_bytes, DownloadCallback callback) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id != null)
		{
			this.status = this.storageClient1.download_file1(fdfs_file_id, file_offset, download_bytes, callback);
		}
		
		return this.status;
	}
	
	/**
	* query file info from storage server
  * @param my_file_id the file id specified by application
	* @return FileInfo object for success, return null for fail
	*/
	public FileInfo query_file_info(String my_file_id) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id == null)
		{
			return null;
		}
		
		FileInfo fileInfo = this.storageClient1.query_file_info1(fdfs_file_id);
		this.status = this.storageClient1.getErrorCode();
		return fileInfo;
	}
	
	/**
	* get file info decoded from filename
  * @param my_file_id the file id specified by application
	* @return FileInfo object for success, return null for fail
	*/
	public FileInfo get_file_info(String my_file_id) throws IOException, MyException
	{
		String fdfs_file_id = this.get_fdfs_file_id(my_file_id);
		if (fdfs_file_id == null)
		{
			return null;
		}
		
		FileInfo fileInfo = this.storageClient1.get_file_info1(fdfs_file_id);
		this.status = this.storageClient1.getErrorCode();
		return fileInfo;
	}
}
