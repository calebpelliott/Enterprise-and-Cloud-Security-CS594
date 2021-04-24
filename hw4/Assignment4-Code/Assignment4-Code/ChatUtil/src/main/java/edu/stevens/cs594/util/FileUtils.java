/*
 * Copyright (C) 2014 Stevens Institute of Technology
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package edu.stevens.cs594.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.logging.Logger;

public class FileUtils {
	
	@SuppressWarnings("unused")
	private static final String TAG = FileUtils.class.getCanonicalName();
	
	@SuppressWarnings("unused")
	private static final Logger logger = Logger.getLogger(FileUtils.class.getCanonicalName());
	

    /**
     * Useful constants
     */
	public final static int BLOCK_SIZE = 1024;
	
    /**
     * File types
     */
	public enum FileType {
		PDF("pdf"),
		PNG("png"),
		MP3("mp3"),
		MP4("mp4"),
		HTML("html"),
		JSON("js"),
		XML("xml"),
		XSD("xsd"),
		XJB("xjb"),
		XSLT("xsl"),
		DATA("data"),
		LOGS("logs"),
		PROPERTIES("properties"),
		TEXT("txt"),
		LOCK("lock"),
		CERTIFICATE("crt"),
		CERT_REQUEST("csr"),
		CERT_EXTERN("pem"),
		CQL("cql"),
		EXCEL("xlsx"),
		CREDENTIALS("p12"),
		JKSCREDENTIALS("jks"),
		CERTIFICATES("bks"),
		JKSCERTIFICATES("jks"),
		CODEBASE("apk");
		private String value;
		private FileType(String v) {
			value = v;
		}
		public String value() {
			return value;
		}
		public static FileType fromValue(String v) {
			for (FileType ft : FileType.values()) {
				if (ft.value.equals(ft)) {
					return ft;
				}
			}
			throw new IllegalArgumentException("Unrecognized file type.");
		}
		
	}
	

	/**
	 * Folder operations
	 */
	
	public static File getFolder(File parent, String folder) {
		return new File(parent, folder);
	}

	public static void ensureFolder(File folder) throws IOException {
		boolean isOk = folder.exists() || folder.mkdirs();
		if (!isOk) {
			throw new FileNotFoundException("Could not create " + folder.getAbsolutePath() + " directory!");
		}
	}
	
	public static boolean isEmpty(File folder) {
		return folder.listFiles().length == 0;
	}
	
	public static boolean deleteFolder(File folder) {
		if (!folder.isDirectory()) {
			throw new IllegalArgumentException("deleteFolder: Not a folder (" + folder.getAbsolutePath() + ")");
			// return false;
		} else if (!isEmpty(folder)) {
			return false;
		} else {
			return folder.delete();
		}
	}
	
	public static boolean deleteContents(File file, String regex) {
		if (file.isDirectory()) {
			for (File child : file.listFiles()) {
				if (child.getAbsoluteFile().getName().matches(regex)) {
					if (!deleteAll(child, regex)) {
						return false;
					}
				}
			}
		}
		return true;
	}

	public static boolean deleteAll(File file) {
		return deleteContents(file, "") && file.delete();
	}
	
	public static boolean deleteAll(File file, String regex) {
		return deleteContents(file, regex) && file.delete();
	}
	
	public static File cwd() {
		return new File(System.getProperty("user.dir"));
	}
	
	/**
	 * File operations
	 */
	
	public static File getFileName(File dir, String name) {
		return new File(dir, name);
	}
	
	public static File getFileName(String name, FileType type) {
		return new File(String.format("%s.%s", name, type.value()));
	}
	
	public static File getFileName(File dir, String name, FileType type) {
		return new File(dir, String.format("%s.%s", name, type.value()));
	}
	
	public static boolean deleteFile(File file) {
		if (!file.isFile()) {
			throw new IllegalArgumentException("deleteFile: Not a file (" + file.getAbsolutePath() + ")");
			// return false;
		} else {
			return file.delete();
		}
	}
	
	public static Writer openOutputCharFile(File file) throws FileNotFoundException {
		CharsetEncoder encoder = Charset.forName(StringUtils.CHARSET).newEncoder();
		return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), encoder));
	}
	
	public static Reader openInputCharFile(File file) throws FileNotFoundException {
		CharsetDecoder decoder = Charset.forName(StringUtils.CHARSET).newDecoder();
		return new BufferedReader(new InputStreamReader(new FileInputStream(file), decoder));
	}
	

	/*
	 * Miscellaneous utilities
	 */
	
	public static void copyFile(Reporter reporter, InputStream from, File to) {
		try {
			ensureFolder(to.getParentFile());
			Files.copy(from, Paths.get(to.toURI()), StandardCopyOption.REPLACE_EXISTING);
		} catch (FileNotFoundException e) {
			reporter.error("File not found.", e);
		} catch (IOException e) {
			reporter.error("Error while reading or writing file.", e);
		}
	}

	public static void copyFile(Reporter reporter, File from, File to) {
		try {
			ensureFolder(to.getParentFile());
			Files.copy(Paths.get(from.toURI()), Paths.get(to.toURI()), StandardCopyOption.REPLACE_EXISTING);
		} catch (FileNotFoundException e) {
			reporter.error("File not found.", e);
		} catch (IOException e) {
			reporter.error("Error while reading or writing file.", e);
		}
	}

	/**
	 * Copy bytes from input to output stream.  Returns actual # of bytes transferred.
	 * @param size
	 * @param is
	 * @param os
	 * @return
	 * @throws IOException
	 */
	public static int copyStream(InputStream is, OutputStream os) throws IOException {
		byte[] buffer = new byte[BLOCK_SIZE];
		int size = 0;
		int nbytes;
		while ((nbytes = is.read(buffer)) >= 0) {
			os.write(buffer, 0, nbytes);
			size += nbytes;
		}
		return size;
	}

	/**
	 * Copy up to "size" bytes from input to output stream.  Returns actual # of bytes transferred.
	 * @param size
	 * @param is
	 * @param os
	 * @return
	 * @throws IOException
	 */
	public static int copyStream(int size, InputStream is, OutputStream os) throws IOException {
		byte[] buffer = new byte[BLOCK_SIZE];
		int numRemain = size;
		int maxBytes = Math.min(numRemain, BLOCK_SIZE);
		int nb;
		while (numRemain > 0 && (nb = is.read(buffer, 0, maxBytes)) >= 0) {
			os.write(buffer, 0, nb);
			numRemain -= nb;
			maxBytes = Math.min(numRemain, BLOCK_SIZE);
		}
		return size - numRemain;
	}

	public static void closeFully(InputStream is) {
		if (is != null) {
			try {
				is.close();
			} catch (Exception e) {
			}
		}
	}

	public static void closeFully(OutputStream is) {
		if (is != null) {
			try {
				is.close();
			} catch (Exception e) {
			}
		}
	}

	public static void closeFully(RandomAccessFile f) {
		if (f != null) {
			try {
				f.close();
			} catch (Exception e) {
			}
		}
	}

	public static void closeFully(Reader rd) {
		if (rd != null) {
			try {
				rd.close();
			} catch (Exception e) {
			}
		}
	}

	public static void closeFully(Writer wr) {
		if (wr != null) {
			try {
				wr.flush();
				wr.close();
			} catch (Exception e) {
			}
		}
	}

	/**
	 * Reading fixed-length blobs on a stream socket.
	 */
	public static byte[] readFixedLengthBlob(InputStream in, int numBytes) throws IOException {
		return FileUtils.readFixedLengthBlob(new DataInputStream(in), numBytes);
	}


	public static byte[] readFixedLengthBlob(DataInputStream in, int numBytes) throws IOException {
		byte[] blob = new byte[numBytes];
		in.readFully(blob);
		return blob;
	}
	
	/**
	 * These operations are taken from the DataInputStream and DataOutputStream libraries.
	 */
	public static void writeInt(OutputStream out, int value) throws IOException {
		out.write((byte) (0xff & (value >> 24)));
		out.write((byte) (0xff & (value >> 16)));
		out.write((byte) (0xff & (value >> 8)));
		out.write((byte) (0xff & value));
	}
	
	public static int readInt(InputStream in) throws IOException {
		byte[] buf = new byte[4];
		readFully(in, buf, 0, 4);
		return convertToInt(buf);
	}
	
	public static void readFully(InputStream in, byte[] buf, int offset, int len) throws IOException {
		if (len < 0) {
			throw new IndexOutOfBoundsException("Negative length: " + len);
		}
		while (len > 0) {
			// in.read will block until some data is available.
			int numread = in.read(buf, offset, len);
			if (numread < 0) {
				throw new EOFException();
			}
			len -= numread;
			offset += numread;
		}
	}
	
	public static void readFully(InputStream in, byte[] buf) throws IOException {
		readFully(in, buf, 0, buf.length);
	}
	
	public static void write(OutputStream out, byte[] buf, int offset, int len) throws IOException {
		for (int i = offset; i < offset + len; i++) {
			out.write(buf[i]);
		}
	}
	
	public static void write(OutputStream out, byte[] buf) throws IOException {
		out.write(buf);
	}
	
	public static int convertToInt(byte[] buf) {
		return (((buf[0] & 0xff) << 24) | 
				((buf[1] & 0xff) << 16) | 
				((buf[2] & 0xff) << 8) | 
				(buf[3] & 0xff));
	}
    
}