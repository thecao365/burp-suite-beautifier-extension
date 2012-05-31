package burp.JSBeautifier;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

public class test {

	/**
	 * @throws IOException 
	 * @throws UnsupportedEncodingException 
	 * @throws URISyntaxException 
	 * @param args
	 * @throws  
	 */
	public static void main(String[] args) {
		String[] fileList = {"beautify-css.js","beautify-html.js","beautify.js","javascriptobfuscator_unpacker.js","myobfuscate_unpacker.js","p_a_c_k_e_r_unpacker.js","urlencode_unpacker.js","inlineJS.js"};
		try{

			String encoding = "UTF-8"; /* You need to know the right character encoding. */
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			URL url = classLoader.getResource("");
			File file = new File(url.toURI());
			InputStream[] fileStreams = new InputStream[fileList.length];
			for (int i=0;i<fileStreams.length;i++){
				fileStreams[i] = new FileInputStream(file+"/"+fileList[i]);
			}

			Enumeration<InputStream> streams = 
					Collections.enumeration(Arrays.asList(fileStreams));
			Reader r = new InputStreamReader(new SequenceInputStream(streams), encoding);
			char[] buf = new char[2048];
			StringBuilder str = new StringBuilder();
			while (true) {
				int n = r.read(buf);
				if (n < 0)
					break;
				str.append(buf, 0, n);
			}
			r.close();
			String contents = str.toString();
		}catch(URISyntaxException errFileName){
			System.err.println("Error: File name is not valid.");
			errFileName.printStackTrace();
		}catch(IOException errIO){
			System.err.println("Error: IO error. Please check the required files: " + fileList.toString());
			errIO.printStackTrace();
		}

	}
}
