package burp.JSBeautifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.SequenceInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import org.mozilla.javascript.*;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.JSBeautifier.UnicodeBOMInputStream.BOM;
import burp.customGUI.ViewHighlightedTextForm;

public class JSBeautifierFunctions {
	private boolean isAutomatic = false; // Automatic or Manual ?
	private final burp.IBurpExtenderCallbacks mCallbacks;
	private String encoding = "UTF-8";
	public static String beautifierJS = "";
	
	// application common messages
	private enum messageList {
		msgNullMessage("Text should not be Null."),
		msgEmptyMessage("Text does not have the required encoding to be beautified, or it is empty."),
		msgReadOnlyMessage("Text is ReadOnly. A new window will be opened shortly."),
		msgFatalMessage("Fatal Error :(\nPlease review the console for the error.");
		private String strMessage;

		private messageList(String msg) {
			strMessage = msg;
		}

		public String getMessage() {
			return strMessage;
		}
	}

	// constructor
	public JSBeautifierFunctions(IBurpExtenderCallbacks mCallbacks) {
		super();
		this.mCallbacks = mCallbacks;
	}

	// This function should be called in order to beautify a message
	public void beautifyIt(IHttpRequestResponse[] messageInfo, boolean isAuto)
	{
		this.isAutomatic = isAuto;
		String[] requestHeaderAndBody = {"",""};
		String[] responsetHeaderAndBody ={"",""};
		String finalRequestHeaderAndBody = "";
		String finalResponsetHeaderAndBody = "";
		int messageState = 0;
		int msgType = 2; // It is a response

		try {

			// There is no option to detect the message type in Burpsuite extender
			// Implementing the message type
			byte[] request = messageInfo[0].getRequest();
			byte[] response = messageInfo[0].getResponse(); 

			// create array of Header and Body for Request and Response
			requestHeaderAndBody = getHeaderAndBody(request);
			responsetHeaderAndBody = getHeaderAndBody(response);

			if(!requestHeaderAndBody[1].equals("") && !responsetHeaderAndBody[1].equals("") && !isNormalPostMessage(requestHeaderAndBody[1]) && !isAutomatic){
				String[] options = {"Only on response", "Only on request", "On both", "Cancel"};
				int n = askConfirmMessage("Please choose an option:", "Response and Request are available, do you want to run beautifier?",options);
				switch(n){
				case 0:
					msgType = 2; // It is a response
					break;
				case 1:
					msgType = 1; // It is a request
					break;
				case 2:
					msgType = 3; // It is both!
					break;
				case 3:
					msgType=0; // Cancel! Then Exit!
					break;
				}
			}else if(requestHeaderAndBody[1].equals("") && responsetHeaderAndBody[1].equals("")){
				msgType=0; // Nothing to be beautified!
			}else{
				msgType = (!responsetHeaderAndBody[1].equals("")) ? 2 : 1; // 1= request, 2= response -> I need to check the response first!
				if(msgType==1 && (isNormalPostMessage(requestHeaderAndBody[1]) || msgType==1 && isAutomatic)){
					// It is a normal POST message and should not be beautified
					msgType= 0;
				}
			}

			// Check the response content-type to be a valid text
			if(msgType==2 || msgType==3){
				if(!isValidContentType(responsetHeaderAndBody[0],responsetHeaderAndBody[1])){
					// Content-Type is not valid, we need to ask the user for confirmation
					int n = 1;
					if(!isAutomatic){
						String[] options = {"Yes, please continue ","No, please do not beautify the response"};
						n = askConfirmMessage("Please choose an option:", "Response content-type has not been recognised, do you still want to run beautifier?",options);
					}
					if(n==1){
						//No has been selected
						if(msgType==2){
							msgType = 0;  // stop beautifying the response
							return; // Exit
						}else{
							msgType = 1; // only beautify the request
						}
					}
				}
			}

			switch(msgType){
			case 3: // It is both!
				requestHeaderAndBody[1] = deCompress(requestHeaderAndBody[1]);
				requestHeaderAndBody[0] = requestHeaderAndBody[0].replaceAll("(?im)^content\\-length:[\\ \\d]+$", "Content-Length: "+requestHeaderAndBody[1].length());

				if(isUnprotectedCSSFile(responsetHeaderAndBody[0],responsetHeaderAndBody[1])){
					// If it is a CSS file, it needs to have a <STYLE> tag in its body, otherwise it will be corrupted
					responsetHeaderAndBody[1] = "<STYLE my/beautifier>"+responsetHeaderAndBody[1]+"</STYLE my/beautifier>";
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("<STYLE my/beautifier>", "");
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("</STYLE my/beautifier>", "");
				}else if(isHtmlXmlFile(responsetHeaderAndBody[0],responsetHeaderAndBody[1])){
					// If it is a HTML or XML file, it should be started with a valid tag
					responsetHeaderAndBody[1] = "<my beautifier unique thing />"+responsetHeaderAndBody[1];
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("<my beautifier unique thing />", "");
				}else{
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
				}

				responsetHeaderAndBody[0] = responsetHeaderAndBody[0].replaceAll("(?im)^content\\-length:[\\ \\d]+$", "Content-Length: "+responsetHeaderAndBody[1].length()+4); // 4 additional characters are "\r\n\r\n" which will be added later
				break;
			case 2:// It is a response
				
				if(isUnprotectedCSSFile(responsetHeaderAndBody[0],responsetHeaderAndBody[1])){
					// If it is a CSS file, it needs to have a <STYLE> tag in its body, otherwise it will be corrupted
					responsetHeaderAndBody[1] = "<STYLE my/beautifier>"+responsetHeaderAndBody[1]+"</STYLE my/beautifier>";
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("<STYLE my/beautifier>", "");
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("</STYLE my/beautifier>", "");
				}else if(isHtmlXmlFile(responsetHeaderAndBody[0],responsetHeaderAndBody[1])){
					// If it is a HTML or XML file, it should be started with a valid tag
					responsetHeaderAndBody[1] = "<my beautifier unique thing />"+responsetHeaderAndBody[1];
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("<my beautifier unique thing />", "");
				}else{
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
				}

				responsetHeaderAndBody[0] = responsetHeaderAndBody[0].replaceAll("(?im)^content\\-length:[\\ \\d]+$", "Content-Length: "+responsetHeaderAndBody[1].length()+4); // 4 additional characters are "\r\n\r\n" which will be added later
				break;
			case 1: // It is a request
				requestHeaderAndBody[1] = deCompress(requestHeaderAndBody[1]);
				requestHeaderAndBody[0] = requestHeaderAndBody[0].replaceAll("(?im)^content\\-length:[\\ \\d]+$", "Content-Length: "+requestHeaderAndBody[1].length());				
				break;
			case 0:
				// Nothing is there! Nothing to be beautified!
				showMessage(messageList.msgEmptyMessage.getMessage());
				return;
			}



			// Create the final/beautified text for Request and Response - They would be empty if they are not available
			finalRequestHeaderAndBody = requestHeaderAndBody[0]+"\r\n\r\n"+requestHeaderAndBody[1];
			finalResponsetHeaderAndBody = responsetHeaderAndBody[0]+"\r\n\r\n"+responsetHeaderAndBody[1];


			if (msgType==1){
				messageInfo[0].setRequest(finalRequestHeaderAndBody.getBytes(encoding));
				messageState = 1;
			}else if (msgType==2){
				messageInfo[0].setResponse(finalResponsetHeaderAndBody.getBytes(encoding));
				messageState = 1;
			}else{
				messageInfo[0].setRequest(finalRequestHeaderAndBody.getBytes(encoding));
				messageState = 1;
				messageInfo[0].setResponse(finalResponsetHeaderAndBody.getBytes(encoding));
				messageState = 2;
			}

		}catch (Exception e) {
			if(e.getMessage().equalsIgnoreCase("Item is read-only") && !isAutomatic)
			{
				// Read only item - we need to open a new message box
				showMessage(messageList.msgReadOnlyMessage.getMessage());

				ViewHighlightedTextForm showMsgForm = new ViewHighlightedTextForm();

				if (msgType==1){
					showMsgForm.showForm(Version.getVersion(), finalRequestHeaderAndBody, "text/html", 600, 450);
				}else if (msgType==2){
					showMsgForm.showForm(Version.getVersion(), finalResponsetHeaderAndBody, "text/html", 600, 450);
				}else{
					if(messageState==0)
						showMsgForm.showForm(Version.getVersion(), finalRequestHeaderAndBody, "text/html", 600, 450);
					showMsgForm.showForm(Version.getVersion(), finalResponsetHeaderAndBody, "text/html", 600, 450);
				}

			}else{
				// Not catched error
				showMessage(messageList.msgFatalMessage.getMessage());
				e.printStackTrace();
			}

		}
	}

	// Running the beautifier javascript on the text
	private String deCompress(String strInput){
		if(strInput==null)
			return "";
		if(strInput.equals(""))
			return "";
		
		String[] testBOMInput = splitBOMCharacter(strInput); // Find any BOM to remove it
		boolean hasBOM = !testBOMInput[0].equals(""); // Does it have BOM?
		// Removing BOM from the input
		if(hasBOM){
			strInput = testBOMInput[1];
		}
		
		
		Context cx = Context.enter();
		String finalResult = "";
		try {
			// Set version to JavaScript1.2 so that we get object-literal style
			// printing instead of "[object Object]"
			// http://jsbeautifier.org/beautify.js
			// Javascripts from "http://jsbeautifier.org/" has been mixed in 1 line - March 2012
			
			// Loading the JavaScript
			if(beautifierJS.equals("")){			
				beautifierJS ="function beautify(a){var b=4;var c=b==1?\"\\t\":\" \";var d=true;var e=false;var f=\"normal\";var g=\"expand\";var h=true;var i=true;var j=a;var k={indent_size:b,indent_char:c,preserve_newlines:d,brace_style:g,keep_array_indentation:e,space_after_anon_function:true,space_before_conditional:h,indent_scripts:f};if(looks_like_html(a)){j=style_html(a,k)}else{if(i){a=unpacker_filter(a)}var j=js_beautify(a,k)}return j}function looks_like_html(a){var b=a.replace(/^[ \\t\\n\\r]+/,\"\");var c=\"<!-\"+\"-\";return b&&b.substring(0,1)===\"<\"&&b.substring(0,4)!==c}function unpacker_filter(a){var b=\"\";var c=\"\";var d=false;do{d=false;if(/^\\s*\\/\\*/.test(a)){d=true;c=a.substr(0,a.indexOf(\"*/\")+2);a=a.substr(c.length).replace(/^\\s+/,\"\");b+=c+\"\\n\"}else if(/^\\s*\\/\\//.test(a)){d=true;c=a.match(/^\\s*\\/\\/.*/)[0];a=a.substr(c.length).replace(/^\\s+/,\"\");b+=c+\"\\n\"}}while(d);if(P_A_C_K_E_R.detect(a)){var e=P_A_C_K_E_R.unpack(a);if(e!=a){a=unpacker_filter(e)}}if(Urlencoded.detect(a)){a=unpacker_filter(Urlencoded.unpack(a))}if(JavascriptObfuscator.detect(a)){a=unpacker_filter(JavascriptObfuscator.unpack(a))}if(MyObfuscate.detect(a)){a=unpacker_filter(MyObfuscate.unpack(a))}return b+a}function style_html(a,b){function h(){this.pos=0;this.token=\"\";this.current_mode=\"CONTENT\";this.tags={parent:\"parent1\",parentcount:1,parent1:\"\"};this.tag_type=\"\";this.token_text=this.last_token=this.last_text=this.token_type=\"\";this.Utils={whitespace:\"\\n\\r\\t \".split(\"\"),single_token:\"br,input,link,meta,!doctype,basefont,base,area,hr,wbr,param,img,isindex,?xml,embed\".split(\",\"),extra_liners:\"head,body,/html\".split(\",\"),in_array:function(a,b){for(var c=0;c<b.length;c++){if(a===b[c]){return true}}return false}};this.get_content=function(){var a=\"\";var b=[];var c=false;while(this.input.charAt(this.pos)!==\"<\"){if(this.pos>=this.input.length){return b.length?b.join(\"\"):[\"\",\"TK_EOF\"]}a=this.input.charAt(this.pos);this.pos++;this.line_char_count++;if(this.Utils.in_array(a,this.Utils.whitespace)){if(b.length){c=true}this.line_char_count--;continue}else if(c){if(this.line_char_count>=this.max_char){b.push(\"\\n\");for(var d=0;d<this.indent_level;d++){b.push(this.indent_string)}this.line_char_count=0}else{b.push(\" \");this.line_char_count++}c=false}b.push(a)}return b.length?b.join(\"\"):\"\"};this.get_contents_to=function(a){if(this.pos==this.input.length){return[\"\",\"TK_EOF\"]}var b=\"\";var c=\"\";var d=new RegExp(\"</\"+a+\"\\\\s*>\",\"igm\");d.lastIndex=this.pos;var e=d.exec(this.input);var f=e?e.index:this.input.length;if(this.pos<f){c=this.input.substring(this.pos,f);this.pos=f}return c};this.record_tag=function(a){if(this.tags[a+\"count\"]){this.tags[a+\"count\"]++;this.tags[a+this.tags[a+\"count\"]]=this.indent_level}else{this.tags[a+\"count\"]=1;this.tags[a+this.tags[a+\"count\"]]=this.indent_level}this.tags[a+this.tags[a+\"count\"]+\"parent\"]=this.tags.parent;this.tags.parent=a+this.tags[a+\"count\"]};this.retrieve_tag=function(a){if(this.tags[a+\"count\"]){var b=this.tags.parent;while(b){if(a+this.tags[a+\"count\"]===b){break}b=this.tags[b+\"parent\"]}if(b){this.indent_level=this.tags[a+this.tags[a+\"count\"]];this.tags.parent=this.tags[b+\"parent\"]}delete this.tags[a+this.tags[a+\"count\"]+\"parent\"];delete this.tags[a+this.tags[a+\"count\"]];if(this.tags[a+\"count\"]==1){delete this.tags[a+\"count\"]}else{this.tags[a+\"count\"]--}}};this.get_tag=function(){var a=\"\";var b=[];var c=false;do{if(this.pos>=this.input.length){return b.length?b.join(\"\"):[\"\",\"TK_EOF\"]}a=this.input.charAt(this.pos);this.pos++;this.line_char_count++;if(this.Utils.in_array(a,this.Utils.whitespace)){c=true;this.line_char_count--;continue}if(a===\"'\"||a==='\"'){if(!b[1]||b[1]!==\"!\"){a+=this.get_unformatted(a);c=true}}if(a===\"=\"){c=false}if(b.length&&b[b.length-1]!==\"=\"&&a!==\">\"&&c){if(this.line_char_count>=this.max_char){this.print_newline(false,b);this.line_char_count=0}else{b.push(\" \");this.line_char_count++}c=false}b.push(a)}while(a!==\">\");var d=b.join(\"\");var e;if(d.indexOf(\" \")!=-1){e=d.indexOf(\" \")}else{e=d.indexOf(\">\")}var f=d.substring(1,e).toLowerCase();if(d.charAt(d.length-2)===\"/\"||this.Utils.in_array(f,this.Utils.single_token)){this.tag_type=\"SINGLE\"}else if(f===\"script\"){this.record_tag(f);this.tag_type=\"SCRIPT\"}else if(f===\"style\"){this.record_tag(f);this.tag_type=\"STYLE\"}else if(this.Utils.in_array(f,unformatted)){var g=this.get_unformatted(\"</\"+f+\">\",d);b.push(g);this.tag_type=\"SINGLE\"}else if(f.charAt(0)===\"!\"){if(f.indexOf(\"[if\")!=-1){if(d.indexOf(\"!IE\")!=-1){var g=this.get_unformatted(\"-->\",d);b.push(g)}this.tag_type=\"START\"}else if(f.indexOf(\"[endif\")!=-1){this.tag_type=\"END\";this.unindent()}else if(f.indexOf(\"[cdata[\")!=-1){var g=this.get_unformatted(\"]]>\",d);b.push(g);this.tag_type=\"SINGLE\"}else{var g=this.get_unformatted(\"-->\",d);b.push(g);this.tag_type=\"SINGLE\"}}else{if(f.charAt(0)===\"/\"){this.retrieve_tag(f.substring(1));this.tag_type=\"END\"}else{this.record_tag(f);this.tag_type=\"START\"}if(this.Utils.in_array(f,this.Utils.extra_liners)){this.print_newline(true,this.output)}}return b.join(\"\")};this.get_unformatted=function(a,b){if(b&&b.indexOf(a)!=-1){return\"\"}var c=\"\";var d=\"\";var e=true;do{if(this.pos>=this.input.length){return d}c=this.input.charAt(this.pos);this.pos++;if(this.Utils.in_array(c,this.Utils.whitespace)){if(!e){this.line_char_count--;continue}if(c===\"\\n\"||c===\"\\r\"){d+=\"\\n\";this.line_char_count=0;continue}}d+=c;this.line_char_count++;e=true}while(d.indexOf(a)==-1);return d};this.get_token=function(){var a;if(this.last_token===\"TK_TAG_SCRIPT\"||this.last_token===\"TK_TAG_STYLE\"){var b=this.last_token.substr(7);a=this.get_contents_to(b);if(typeof a!==\"string\"){return a}return[a,\"TK_\"+b]}if(this.current_mode===\"CONTENT\"){a=this.get_content();if(typeof a!==\"string\"){return a}else{return[a,\"TK_CONTENT\"]}}if(this.current_mode===\"TAG\"){a=this.get_tag();if(typeof a!==\"string\"){return a}else{var c=\"TK_TAG_\"+this.tag_type;return[a,c]}}};this.get_full_indent=function(a){a=this.indent_level+a||0;if(a<1)return\"\";return Array(a+1).join(this.indent_string)};this.printer=function(a,b,c,d,e){this.input=a||\"\";this.output=[];this.indent_character=b;this.indent_string=\"\";this.indent_size=c;this.brace_style=e;this.indent_level=0;this.max_char=d;this.line_char_count=0;for(var f=0;f<this.indent_size;f++){this.indent_string+=this.indent_character}this.print_newline=function(a,b){this.line_char_count=0;if(!b||!b.length){return}if(!a){while(this.Utils.in_array(b[b.length-1],this.Utils.whitespace)){b.pop()}}b.push(\"\\n\");for(var c=0;c<this.indent_level;c++){b.push(this.indent_string)}};this.print_token=function(a){this.output.push(a)};this.indent=function(){this.indent_level++};this.unindent=function(){if(this.indent_level>0){this.indent_level--}}};return this}var c,d,e,f,g;b=b||{};d=b.indent_size||4;e=b.indent_char||\" \";g=b.brace_style||\"collapse\";f=b.max_char==0?Infinity:b.max_char||70;unformatted=b.unformatted||[\"a\"];c=new h;c.printer(a,e,d,f,g);while(true){var i=c.get_token();c.token_text=i[0];c.token_type=i[1];if(c.token_type===\"TK_EOF\"){break}switch(c.token_type){case\"TK_TAG_START\":c.print_newline(false,c.output);c.print_token(c.token_text);c.indent();c.current_mode=\"CONTENT\";break;case\"TK_TAG_STYLE\":case\"TK_TAG_SCRIPT\":c.print_newline(false,c.output);c.print_token(c.token_text);c.current_mode=\"CONTENT\";break;case\"TK_TAG_END\":if(c.last_token===\"TK_CONTENT\"&&c.last_text===\"\"){var j=c.token_text.match(/\\w+/)[0];var k=c.output[c.output.length-1].match(/<\\s*(\\w+)/);if(k===null||k[1]!==j)c.print_newline(true,c.output)}c.print_token(c.token_text);c.current_mode=\"CONTENT\";break;case\"TK_TAG_SINGLE\":c.print_newline(false,c.output);c.print_token(c.token_text);c.current_mode=\"CONTENT\";break;case\"TK_CONTENT\":if(c.token_text!==\"\"){c.print_token(c.token_text)}c.current_mode=\"TAG\";break;case\"TK_STYLE\":case\"TK_SCRIPT\":if(c.token_text!==\"\"){c.output.push(\"\\n\");var l=c.token_text;if(c.token_type==\"TK_SCRIPT\"){var m=typeof js_beautify==\"function\"&&js_beautify}else if(c.token_type==\"TK_STYLE\"){var m=typeof css_beautify==\"function\"&&css_beautify}if(b.indent_scripts==\"keep\"){var n=0}else if(b.indent_scripts==\"separate\"){var n=-c.indent_level}else{var n=1}var o=c.get_full_indent(n);if(m){l=m(l.replace(/^\\s*/,o),b)}else{var p=l.match(/^\\s*/)[0];var q=p.match(/[^\\n\\r]*$/)[0].split(c.indent_string).length-1;var r=c.get_full_indent(n-q);l=l.replace(/^\\s*/,o).replace(/\\r\\n|\\r|\\n/g,\"\\n\"+r).replace(/\\s*$/,\"\")}if(l){c.print_token(l);c.print_newline(true,c.output)}}c.current_mode=\"TAG\";break}c.last_token=c.token_type;c.last_text=c.token_text}return c.output.join(\"\")}function css_beautify(a,b){function t(){r--;p=p.slice(0,-c)}function s(){r++;p+=q}function o(a,b){return u.slice(-a.length+(b||0),b).join(\"\").toLowerCase()==a}function n(){var b=g;i();while(i()){if(h==\"*\"&&j()==\"/\"){g++;break}}return a.substring(b,g+1)}function m(){var a=g;do{}while(e.test(i()));return g!=a+1}function l(){var a=g;while(e.test(j()))g++;return g!=a}function k(b){var c=g;while(i()){if(h==\"\\\\\"){i();i()}else if(h==b){break}else if(h==\"\\n\"){break}}return a.substring(c,g+1)}function j(){return a.charAt(g+1)}function i(){return h=a.charAt(++g)}b=b||{};var c=b.indent_size||4;var d=b.indent_char||\" \";if(typeof c==\"string\")c=parseInt(c);var e=/^\\s+$/;var f=/[\\w$\\-_]/;var g=-1,h;var p=a.match(/^[\\r\\n]*[\\t ]*/)[0];var q=Array(c+1).join(d);var r=0;print={};print[\"{\"]=function(a){print.singleSpace();u.push(a);print.newLine()};print[\"}\"]=function(a){print.newLine();u.push(a);print.newLine()};print.newLine=function(a){if(!a)while(e.test(u[u.length-1]))u.pop();if(u.length)u.push(\"\\n\");if(p)u.push(p)};print.singleSpace=function(){if(u.length&&!e.test(u[u.length-1]))u.push(\" \")};var u=[];if(p)u.push(p);while(true){var v=m();if(!h)break;if(h==\"{\"){s();print[\"{\"](h)}else if(h==\"}\"){t();print[\"}\"](h)}else if(h=='\"'||h==\"'\"){u.push(k(h))}else if(h==\";\"){u.push(h,\"\\n\",p)}else if(h==\"/\"&&j()==\"*\"){print.newLine();u.push(n(),\"\\n\",p)}else if(h==\"(\"){u.push(h);l();if(o(\"url\",-1)&&i()){if(h!=\")\"&&h!='\"'&&h!=\"'\")u.push(k(\")\"));else g--}}else if(h==\")\"){u.push(h)}else if(h==\",\"){l();u.push(h);print.singleSpace()}else if(h==\"]\"){u.push(h)}else if(h==\"[\"||h==\"=\"){l();u.push(h)}else{if(v)print.singleSpace();u.push(h)}}var w=u.join(\"\").replace(/[\\n ]+$/,\"\");return w}function js_beautify(a,b){function Z(){x=0;if(p>=I){return[\"\",\"TK_EOF\"]}v=false;var a=c.charAt(p);p+=1;var b=F&&S(j.mode);if(b){var e=0;while(X(a,m)){if(a===\"\\n\"){J();d.push(\"\\n\");w=true;e=0}else{if(a===\"\\t\"){e+=4}else if(a===\"\\r\"){}else{e+=1}}if(p>=I){return[\"\",\"TK_EOF\"]}a=c.charAt(p);p+=1}if(j.indentation_baseline===-1){j.indentation_baseline=e}if(w){var h;for(h=0;h<j.indentation_level+1;h+=1){d.push(l)}if(j.indentation_baseline!==-1){for(h=0;h<e-j.indentation_baseline;h++){d.push(\" \")}}}}else{while(X(a,m)){if(a===\"\\n\"){x+=D?x<=D?1:0:1}if(p>=I){return[\"\",\"TK_EOF\"]}a=c.charAt(p);p+=1}if(C){if(x>1){for(h=0;h<x;h+=1){M(h===0);w=true}}}v=x>0}if(X(a,n)){if(p<I){while(X(c.charAt(p),n)){a+=c.charAt(p);p+=1;if(p===I){break}}}if(p!==I&&a.match(/^[0-9]+[Ee]$/)&&(c.charAt(p)===\"-\"||c.charAt(p)===\"+\")){var i=c.charAt(p);p+=1;var k=Z(p);a+=i+k[0];return[a,\"TK_WORD\"]}if(a===\"in\"){return[a,\"TK_OPERATOR\"]}if(v&&f!==\"TK_OPERATOR\"&&f!==\"TK_EQUALS\"&&!j.if_line&&(C||g!==\"var\")){M()}return[a,\"TK_WORD\"]}if(a===\"(\"||a===\"[\"){return[a,\"TK_START_EXPR\"]}if(a===\")\"||a===\"]\"){return[a,\"TK_END_EXPR\"]}if(a===\"{\"){return[a,\"TK_START_BLOCK\"]}if(a===\"}\"){return[a,\"TK_END_BLOCK\"]}if(a===\";\"){return[a,\"TK_SEMICOLON\"]}if(a===\"/\"){var q=\"\";var s=true;if(c.charAt(p)===\"*\"){p+=1;if(p<I){while(!(c.charAt(p)===\"*\"&&c.charAt(p+1)&&c.charAt(p+1)===\"/\")&&p<I){a=c.charAt(p);q+=a;if(a===\"\\r\"||a===\"\\n\"){s=false}p+=1;if(p>=I){break}}}p+=2;if(s&&x==0){return[\"/*\"+q+\"*/\",\"TK_INLINE_COMMENT\"]}else{return[\"/*\"+q+\"*/\",\"TK_BLOCK_COMMENT\"]}}if(c.charAt(p)===\"/\"){q=a;while(c.charAt(p)!==\"\\r\"&&c.charAt(p)!==\"\\n\"){q+=c.charAt(p);p+=1;if(p>=I){break}}p+=1;if(v){M()}return[q,\"TK_COMMENT\"]}}if(a===\"'\"||a==='\"'||a===\"/\"&&(f===\"TK_WORD\"&&W(g)||g===\")\"&&X(j.previous_mode,[\"(COND-EXPRESSION)\",\"(FOR-EXPRESSION)\"])||f===\"TK_COMMENT\"||f===\"TK_START_EXPR\"||f===\"TK_START_BLOCK\"||f===\"TK_END_BLOCK\"||f===\"TK_OPERATOR\"||f===\"TK_EQUALS\"||f===\"TK_EOF\"||f===\"TK_SEMICOLON\")){var t=a;var u=false;var y=a;if(p<I){if(t===\"/\"){var z=false;while(u||z||c.charAt(p)!==t){y+=c.charAt(p);if(!u){u=c.charAt(p)===\"\\\\\";if(c.charAt(p)===\"[\"){z=true}else if(c.charAt(p)===\"]\"){z=false}}else{u=false}p+=1;if(p>=I){return[y,\"TK_STRING\"]}}}else{while(u||c.charAt(p)!==t){y+=c.charAt(p);if(!u){u=c.charAt(p)===\"\\\\\"}else{u=false}p+=1;if(p>=I){return[y,\"TK_STRING\"]}}}}p+=1;y+=t;if(t===\"/\"){while(p<I&&X(c.charAt(p),n)){y+=c.charAt(p);p+=1}}return[y,\"TK_STRING\"]}if(a===\"#\"){if(d.length===0&&c.charAt(p)===\"!\"){y=a;while(p<I&&a!=\"\\n\"){a=c.charAt(p);y+=a;p+=1}d.push(K(y)+\"\\n\");M();return Z()}var A=\"#\";if(p<I&&X(c.charAt(p),r)){do{a=c.charAt(p);A+=a;p+=1}while(p<I&&a!==\"#\"&&a!==\"=\");if(a===\"#\"){}else if(c.charAt(p)===\"[\"&&c.charAt(p+1)===\"]\"){A+=\"[]\";p+=2}else if(c.charAt(p)===\"{\"&&c.charAt(p+1)===\"}\"){A+=\"{}\";p+=2}return[A,\"TK_WORD\"]}}if(a===\"<\"&&c.substring(p-1,p+3)===\"<!--\"){p+=3;a=\"<!--\";while(c[p]!=\"\\n\"&&p<I){a+=c[p];p++}j.in_html_comment=true;return[a,\"TK_COMMENT\"]}if(a===\"-\"&&j.in_html_comment&&c.substring(p-1,p+2)===\"-->\"){j.in_html_comment=false;p+=2;if(v){M()}return[\"-->\",\"TK_COMMENT\"]}if(X(a,o)){while(p<I&&X(a+c.charAt(p),o)){a+=c.charAt(p);p+=1;if(p>=I){break}}if(a===\"=\"){return[a,\"TK_EQUALS\"]}else{return[a,\"TK_OPERATOR\"]}}return[a,\"TK_UNKNOWN\"]}function Y(a){var b=p;var d=c.charAt(b);while(X(d,m)&&d!=a){b++;if(b>=I)return 0;d=c.charAt(b)}return d}function X(a,b){for(var c=0;c<b.length;c+=1){if(b[c]===a){return true}}return false}function W(a){return X(a,[\"case\",\"return\",\"do\",\"if\",\"throw\",\"else\"])}function V(a,b){for(var c=0;c<a.length;c++){if(K(a[c])[0]!=b){return false}}return true}function U(){u=j.mode===\"DO_BLOCK\";if(k.length>0){var a=j.mode;j=k.pop();j.previous_mode=a}}function T(a){return X(a,[\"[EXPRESSION]\",\"(EXPRESSION)\",\"(FOR-EXPRESSION)\",\"(COND-EXPRESSION)\"])}function S(a){return a===\"[EXPRESSION]\"||a===\"[INDENTED-EXPRESSION]\"}function R(a){if(j){k.push(j)}j={previous_mode:j?j.mode:\"BLOCK\",mode:a,var_line:false,var_line_tainted:false,var_line_reindented:false,in_html_comment:false,if_line:false,in_case:false,case_body:false,eat_next_space:false,indentation_baseline:-1,indentation_level:j?j.indentation_level+(j.case_body?1:0)+(j.var_line&&j.var_line_reindented?1:0):0,ternary_depth:0}}function Q(){if(d.length&&d[d.length-1]===l){d.pop()}}function P(){j.indentation_level+=1}function O(){w=false;j.eat_next_space=false;d.push(e)}function N(){if(f===\"TK_COMMENT\"){return M(true)}if(j.eat_next_space){j.eat_next_space=false;return}var a=\" \";if(d.length){a=d[d.length-1]}if(a!==\" \"&&a!==\"\\n\"&&a!==l){d.push(\" \")}}function M(a){j.eat_next_space=false;if(F&&S(j.mode)){return}a=typeof a===\"undefined\"?true:a;j.if_line=false;J();if(!d.length){return}if(d[d.length-1]!==\"\\n\"||!a){w=true;d.push(\"\\n\")}if(y){d.push(y)}for(var b=0;b<j.indentation_level;b+=1){d.push(l)}if(j.var_line&&j.var_line_reindented){d.push(l)}if(j.case_body){d.push(l)}}function L(){var a=F;F=false;M();F=a}function K(a){return a.replace(/^\\s\\s*|\\s\\s*$/,\"\")}function J(a){a=typeof a===\"undefined\"?false:a;while(d.length&&(d[d.length-1]===\" \"||d[d.length-1]===l||d[d.length-1]===y||a&&(d[d.length-1]===\"\\n\"||d[d.length-1]===\"\\r\"))){d.pop()}}var c,d,e,f,g,h,i,j,k,l;var m,n,o,p,q,r;var s,t,u;var v,w,x;var y=\"\";b=b?b:{};var z;if(b.space_after_anon_function!==undefined&&b.jslint_happy===undefined){b.jslint_happy=b.space_after_anon_function}if(b.braces_on_own_line!==undefined){z=b.braces_on_own_line?\"expand\":\"collapse\"}z=b.brace_style?b.brace_style:z?z:\"collapse\";var A=b.indent_size?b.indent_size:4;var B=b.indent_char?b.indent_char:\" \";var C=typeof b.preserve_newlines===\"undefined\"?true:b.preserve_newlines;var D=typeof b.max_preserve_newlines===\"undefined\"?false:b.max_preserve_newlines;var E=b.jslint_happy===\"undefined\"?false:b.jslint_happy;var F=typeof b.keep_array_indentation===\"undefined\"?false:b.keep_array_indentation;var G=typeof b.space_before_conditional===\"undefined\"?true:b.space_before_conditional;var H=typeof b.indent_case===\"undefined\"?false:b.indent_case;w=false;var I=a.length;l=\"\";while(A>0){l+=B;A-=1}while(a&&(a[0]===\" \"||a[0]===\"\\t\")){y+=a[0];a=a.substring(1)}c=a;i=\"\";f=\"TK_START_EXPR\";g=\"\";h=\"\";d=[];u=false;m=\"\\n\\r\\t \".split(\"\");n=\"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$\".split(\"\");r=\"0123456789\".split(\"\");o=\"+ - * / % & ++ -- = += -= *= /= %= == === != !== > < >= <= >> << >>> >>>= >>= <<= && &= | || ! !! , : ? ^ ^= |= ::\";o+=\" <%= <% %> <?= <? ?>\";o=o.split(\" \");q=\"continue,try,throw,return,var,if,switch,case,default,for,while,break,function\".split(\",\");k=[];R(\"BLOCK\");p=0;while(true){var $=Z(p);e=$[0];t=$[1];if(t===\"TK_EOF\"){break}switch(t){case\"TK_START_EXPR\":if(e===\"[\"){if(f===\"TK_WORD\"||g===\")\"){if(X(g,q)){N()}R(\"(EXPRESSION)\");O();break}if(j.mode===\"[EXPRESSION]\"||j.mode===\"[INDENTED-EXPRESSION]\"){if(h===\"]\"&&g===\",\"){if(j.mode===\"[EXPRESSION]\"){j.mode=\"[INDENTED-EXPRESSION]\";if(!F){P()}}R(\"[EXPRESSION]\");if(!F){M()}}else if(g===\"[\"){if(j.mode===\"[EXPRESSION]\"){j.mode=\"[INDENTED-EXPRESSION]\";if(!F){P()}}R(\"[EXPRESSION]\");if(!F){M()}}else{R(\"[EXPRESSION]\")}}else{R(\"[EXPRESSION]\")}}else{if(i===\"for\"){R(\"(FOR-EXPRESSION)\")}else if(X(i,[\"if\",\"while\"])){R(\"(COND-EXPRESSION)\")}else{R(\"(EXPRESSION)\")}}if(g===\";\"||f===\"TK_START_BLOCK\"){M()}else if(f===\"TK_END_EXPR\"||f===\"TK_START_EXPR\"||f===\"TK_END_BLOCK\"||g===\".\"){if(v){M()}}else if(f!==\"TK_WORD\"&&f!==\"TK_OPERATOR\"){N()}else if(i===\"function\"||i===\"typeof\"){if(E){N()}}else if(X(g,q)||g===\"catch\"){if(G){N()}}O();break;case\"TK_END_EXPR\":if(e===\"]\"){if(F){if(g===\"}\"){Q();O();U();break}}else{if(j.mode===\"[INDENTED-EXPRESSION]\"){if(g===\"]\"){U();M();O();break}}}}U();O();break;case\"TK_START_BLOCK\":if(i===\"do\"){R(\"DO_BLOCK\")}else{R(\"BLOCK\")}if(z==\"expand\"||z==\"expand-strict\"){var _=false;if(z==\"expand-strict\"){_=Y()==\"}\";if(!_){M(true)}}else{if(f!==\"TK_OPERATOR\"){if(g===\"=\"||W(g)&&g!==\"else\"){N()}else{M(true)}}}O();if(!_)P()}else{if(f!==\"TK_OPERATOR\"&&f!==\"TK_START_EXPR\"){if(f===\"TK_START_BLOCK\"){M()}else{N()}}else{if(S(j.previous_mode)&&g===\",\"){if(h===\"}\"){N()}else{M()}}}P();O()}break;case\"TK_END_BLOCK\":U();if(z==\"expand\"||z==\"expand-strict\"){if(g!==\"{\"){M()}O()}else{if(f===\"TK_START_BLOCK\"){if(w){Q()}else{J()}}else{if(S(j.mode)&&F){F=false;M();F=true}else{M()}}O()}break;case\"TK_WORD\":if(u){N();O();N();u=false;break}if(e===\"function\"){if(j.var_line){j.var_line_reindented=true}if((w||g===\";\")&&g!==\"{\"&&f!=\"TK_BLOCK_COMMENT\"&&f!=\"TK_COMMENT\"){x=w?x:0;if(!C){x=1}for(var ba=0;ba<2-x;ba++){M(false)}}}if(e===\"case\"||e===\"default\"){if(g===\":\"||j.case_body){Q()}else{if(!H)j.indentation_level--;M();if(!H)j.indentation_level++}O();j.in_case=true;j.case_body=false;break}s=\"NONE\";if(f===\"TK_END_BLOCK\"){if(!X(e.toLowerCase(),[\"else\",\"catch\",\"finally\"])){s=\"NEWLINE\"}else{if(z==\"expand\"||z==\"end-expand\"||z==\"expand-strict\"){s=\"NEWLINE\"}else{s=\"SPACE\";N()}}}else if(f===\"TK_SEMICOLON\"&&(j.mode===\"BLOCK\"||j.mode===\"DO_BLOCK\")){s=\"NEWLINE\"}else if(f===\"TK_SEMICOLON\"&&T(j.mode)){s=\"SPACE\"}else if(f===\"TK_STRING\"){s=\"NEWLINE\"}else if(f===\"TK_WORD\"){if(g===\"else\"){J(true)}s=\"SPACE\"}else if(f===\"TK_START_BLOCK\"){s=\"NEWLINE\"}else if(f===\"TK_END_EXPR\"){N();s=\"NEWLINE\"}if(X(e,q)&&g!==\")\"){if(g==\"else\"){s=\"SPACE\"}else{s=\"NEWLINE\"}if(e===\"function\"&&(g===\"get\"||g===\"set\")){s=\"SPACE\"}}if(j.if_line&&f===\"TK_END_EXPR\"){j.if_line=false}if(X(e.toLowerCase(),[\"else\",\"catch\",\"finally\"])){if(f!==\"TK_END_BLOCK\"||z==\"expand\"||z==\"end-expand\"||z==\"expand-strict\"){M()}else{J(true);N()}}else if(s===\"NEWLINE\"){if((f===\"TK_START_EXPR\"||g===\"=\"||g===\",\")&&e===\"function\"){}else if(e===\"function\"&&g==\"new\"){N()}else if(W(g)){N()}else if(f!==\"TK_END_EXPR\"){if((f!==\"TK_START_EXPR\"||e!==\"var\")&&g!==\":\"){if(e===\"if\"&&i===\"else\"&&g!==\"{\"){N()}else{j.var_line=false;j.var_line_reindented=false;M()}}}else if(X(e,q)&&g!=\")\"){j.var_line=false;j.var_line_reindented=false;M()}}else if(S(j.mode)&&g===\",\"&&h===\"}\"){M()}else if(s===\"SPACE\"){N()}O();i=e;if(e===\"var\"){j.var_line=true;j.var_line_reindented=false;j.var_line_tainted=false}if(e===\"if\"){j.if_line=true}if(e===\"else\"){j.if_line=false}break;case\"TK_SEMICOLON\":O();j.var_line=false;j.var_line_reindented=false;if(j.mode==\"OBJECT\"){j.mode=\"BLOCK\"}break;case\"TK_STRING\":if(f===\"TK_END_EXPR\"&&X(j.previous_mode,[\"(COND-EXPRESSION)\",\"(FOR-EXPRESSION)\"])){N()}else if(f==\"TK_STRING\"||f===\"TK_START_BLOCK\"||f===\"TK_END_BLOCK\"||f===\"TK_SEMICOLON\"){M()}else if(f===\"TK_WORD\"){N()}O();break;case\"TK_EQUALS\":if(j.var_line){j.var_line_tainted=true}N();O();N();break;case\"TK_OPERATOR\":var bb=true;var bc=true;if(j.var_line&&e===\",\"&&T(j.mode)){j.var_line_tainted=false}if(j.var_line){if(e===\",\"){if(j.var_line_tainted){O();j.var_line_reindented=true;j.var_line_tainted=false;M();break}else{j.var_line_tainted=false}}}if(W(g)){N();O();break}if(e===\":\"&&j.in_case){if(H)j.case_body=true;O();M();j.in_case=false;break}if(e===\"::\"){O();break}if(e===\",\"){if(j.var_line){if(j.var_line_tainted){O();M();j.var_line_tainted=false}else{O();N()}}else if(f===\"TK_END_BLOCK\"&&j.mode!==\"(EXPRESSION)\"){O();if(j.mode===\"OBJECT\"&&g===\"}\"){M()}else{N()}}else{if(j.mode===\"OBJECT\"){O();M()}else{O();N()}}break}else if(X(e,[\"--\",\"++\",\"!\"])||X(e,[\"-\",\"+\"])&&(X(f,[\"TK_START_BLOCK\",\"TK_START_EXPR\",\"TK_EQUALS\",\"TK_OPERATOR\"])||X(g,q))){bb=false;bc=false;if(g===\";\"&&T(j.mode)){bb=true}if(f===\"TK_WORD\"&&X(g,q)){bb=true}if(j.mode===\"BLOCK\"&&(g===\"{\"||g===\";\")){M()}}else if(e===\".\"){bb=false}else if(e===\":\"){if(j.ternary_depth==0){j.mode=\"OBJECT\";bb=false}else{j.ternary_depth-=1}}else if(e===\"?\"){j.ternary_depth+=1}if(bb){N()}O();if(bc){N()}if(e===\"!\"){}break;case\"TK_BLOCK_COMMENT\":var bd=e.split(/\\x0a|\\x0d\\x0a/);if(V(bd.slice(1),\"*\")){M();d.push(bd[0]);for(ba=1;ba<bd.length;ba++){M();d.push(\" \");d.push(K(bd[ba]))}}else{if(bd.length>1){M()}else{if(f===\"TK_END_BLOCK\"){M()}else{N()}}for(ba=0;ba<bd.length;ba++){d.push(bd[ba]);d.push(\"\\n\")}}if(Y(\"\\n\")!=\"\\n\")M();break;case\"TK_INLINE_COMMENT\":N();O();if(T(j.mode)){N()}else{L()}break;case\"TK_COMMENT\":if(v){M()}else{N()}O();if(Y(\"\\n\")!=\"\\n\")L();break;case\"TK_UNKNOWN\":if(W(g)){N()}O();break}h=g;f=t;g=e}var be=y+d.join(\"\").replace(/[\\n ]+$/,\"\");return be}if(typeof exports!==\"undefined\")exports.js_beautify=js_beautify;if(typeof exports!==\"undefined\")exports.css_beautify=css_beautify;var JavascriptObfuscator={detect:function(a){return/^var _0x[a-f0-9]+ ?\\= ?\\[/.test(a)},unpack:function(a){if(JavascriptObfuscator.detect(a)){var b=/var (_0x[a-f\\d]+) ?\\= ?\\[(.*?)\\];/.exec(a);if(b){var c=b[1];var d=JavascriptObfuscator._smart_split(b[2]);var a=a.substring(b[0].length);for(var e in d){a=a.replace(new RegExp(c+\"\\\\[\"+e+\"\\\\]\",\"g\"),JavascriptObfuscator._fix_quotes(JavascriptObfuscator._unescape(d[e])))}}}return a},_fix_quotes:function(a){var b=/^\"(.*)\"$/.exec(a);if(b){a=b[1];a=\"'\"+a.replace(/'/g,\"\\\\'\")+\"'\"}return a},_smart_split:function(a){var b=[];var c=0;while(c<a.length){if(a.charAt(c)=='\"'){var d=\"\";c+=1;while(c<a.length){if(a.charAt(c)=='\"'){break}if(a.charAt(c)==\"\\\\\"){d+=\"\\\\\";c++}d+=a.charAt(c);c++}b.push('\"'+d+'\"')}c+=1}return b},_unescape:function(a){for(var b=32;b<128;b++){a=a.replace(new RegExp(\"\\\\\\\\x\"+b.toString(16),\"ig\"),String.fromCharCode(b))}return a},run_tests:function(a){var b=a||new SanityTest;b.test_function(JavascriptObfuscator._smart_split,\"JavascriptObfuscator._smart_split\");b.expect(\"\",[]);b.expect('\"a\", \"b\"',['\"a\"','\"b\"']);b.expect('\"aaa\",\"bbbb\"',['\"aaa\"','\"bbbb\"']);b.expect('\"a\", \"b\\\\\"\"',['\"a\"','\"b\\\\\"\"']);b.test_function(JavascriptObfuscator._unescape,\"JavascriptObfuscator._unescape\");b.expect(\"\\\\x40\",\"@\");b.expect(\"\\\\x10\",\"\\\\x10\");b.expect(\"\\\\x1\",\"\\\\x1\");b.expect(\"\\\\x61\\\\x62\\\\x22\\\\x63\\\\x64\",'ab\"cd');b.test_function(JavascriptObfuscator.detect,\"JavascriptObfuscator.detect\");b.expect(\"\",false);b.expect(\"abcd\",false);b.expect(\"var _0xaaaa\",false);b.expect('var _0xaaaa = [\"a\", \"b\"]',true);b.expect('var _0xaaaa=[\"a\", \"b\"]',true);b.expect('var _0x1234=[\"a\",\"b\"]',true);return b}};var Urlencoded={detect:function(a){if(a.indexOf(\" \")==-1){if(a.indexOf(\"%20\")!=-1)return true;if(a.replace(/[^%]+/g,\"\").length>3)return true}return false},unpack:function(a){if(Urlencoded.detect(a)){return unescape(a.replace(/\\+/g,\"%20\"))}return a},run_tests:function(a){var b=a||new SanityTest;b.test_function(Urlencoded.detect,\"Urlencoded.detect\");b.expect(\"\",false);b.expect(\"var a = b\",false);b.expect(\"var%20a+=+b\",true);b.expect(\"var%20a=b\",true);b.expect(\"var%20%21%22\",true);b.test_function(Urlencoded.unpack,\"Urlencoded.unpack\");b.expect(\"\",\"\");b.expect(\"abcd\",\"abcd\");b.expect(\"var a = b\",\"var a = b\");b.expect(\"var%20a=b\",\"var a=b\");b.expect(\"var%20a+=+b\",\"var a = b\");return b}};var P_A_C_K_E_R={detect:function(a){return P_A_C_K_E_R._starts_with(a.toLowerCase().replace(/ +/g,\"\"),\"eval(function(\")||P_A_C_K_E_R._starts_with(a.toLowerCase().replace(/ +/g,\"\"),\"eval((function(\")},unpack:function(str){var unpacked_source=\"\";if(P_A_C_K_E_R.detect(str)){try{eval(\"unpacked_source = \"+str.substring(4)+\";\");if(typeof unpacked_source==\"string\"&&unpacked_source){str=unpacked_source}}catch(error){}}return str},_starts_with:function(a,b){return a.substr(0,b.length)===b},run_tests:function(a){var b=a||new SanityTest;b.test_function(P_A_C_K_E_R.detect,\"P_A_C_K_E_R.detect\");b.expect(\"\",false);b.expect(\"var a = b\",false);b.expect(\"eval(function(p,a,c,k,e,r\",true);b.expect(\"eval ( function(p, a, c, k, e, r\",true);b.test_function(P_A_C_K_E_R.unpack,\"P_A_C_K_E_R.unpack\");b.expect(\"eval(function(p,a,c,k,e,r){e=String;if(!''.replace(/^/,String)){while(c--)r[c]=k[c]||c;k=[function(e){return r[e]}];e=function(){return'\\\\\\\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\\\\\\\b'+e(c)+'\\\\\\\\b','g'),k[c]);return p}('0 2=1',3,3,'var||a'.split('|'),0,{}))\",\"var a=1\");var c=function(a){return P_A_C_K_E_R._starts_with(a,\"a\")};b.test_function(c,\"P_A_C_K_E_R._starts_with(?, a)\");b.expect(\"abc\",true);b.expect(\"bcd\",false);b.expect(\"a\",true);b.expect(\"\",false);return b}};var MyObfuscate={detect:function(a){return/^var _?[0O1lI]{3}\\=('|\\[).*\\)\\)\\);/.test(a)},unpack:function(str){if(MyObfuscate.detect(str)){var modified_source=str.replace(\";eval(\",\";unpacked_source = (\");var unpacked_source=\"\";eval(modified_source);if(unpacked_source){if(MyObfuscate.starts_with(unpacked_source,\"var _escape\")){var matches=/'([^']*)'/.exec(unpacked_source);var unescaped=unescape(matches[1]);if(MyObfuscate.starts_with(unescaped,\"<script>\")){unescaped=unescaped.substr(8,unescaped.length-8)}if(MyObfuscate.ends_with(unescaped,\"<\"+\"/script>\")){unescaped=unescaped.substr(0,unescaped.length-9)}unpacked_source=unescaped}}return unpacked_source?\"// Unpacker warning: be careful when using myobfuscate.com for your projects:\\n\"+\"// scripts obfuscated by the free online version call back home.\\n\"+\"\\n//\\n\"+unpacked_source:str}return str},starts_with:function(a,b){return a.substr(0,b.length)===b},ends_with:function(a,b){return a.substr(a.length-b.length,b.length)===b},run_tests:function(a){var b=a||new SanityTest;return b}}";
				String[] fileList = {"beautify-css.js","beautify-html.js","beautify.js","javascriptobfuscator_unpacker.js","myobfuscate_unpacker.js","p_a_c_k_e_r_unpacker.js","urlencode_unpacker.js","inlineJS.js"};
				try{
	
					String encoding = "UTF-8"; /* You need to know the right character encoding. */
//					ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
//					URL url = classLoader.getResource("");
//					System.out.println(url);////////// NULL????????
//					
//					File file = new File(url.toURI());
					InputStream[] fileStreams = new InputStream[fileList.length];
					for (int i=0;i<fileStreams.length;i++){
//						fileStreams[i] = new FileInputStream(file+"/"+fileList[i]);
						fileStreams[i] = getClass().getResourceAsStream("/"+fileList[i]);
						
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
					beautifierJS = str.toString();
					System.out.println("Javascript files have been loaded successfully.");
//				}catch(URISyntaxException errFileName){
//					System.err.println("Error: File name(s) is/are not valid." + fileList.toString());
//					errFileName.printStackTrace();
//					System.out.println("Unable to load the JavaScript files. Hardcoded JS string will be used.");
				}catch(IOException errIO){
					System.err.println("Error: IO error. Please check the required files: " + fileList.toString());
					errIO.printStackTrace();
					System.out.println("Unable to load the JavaScript files. Hardcoded JS string will be used.");
				}
			}
			cx.setLanguageVersion(Context.VERSION_DEFAULT);


			// Initialize the standard objects (Object, Function, etc.)
			// This must be done before scripts can be executed.
			Scriptable scope = cx.initStandardObjects();

			// Now we can evaluate a script. Let's create a new object
			// using the object literal notation.
			Object result = cx.evaluateString(scope, beautifierJS,"myBeautifier", 1, null);

			Object fObj = scope.get("beautify", scope);

			if (!(fObj instanceof Function)) {
				System.out.println("beautify is undefined or not a function.");
			} else {
				Object functionArgs[] = { strInput };
				Function f = (Function)fObj;
				Object result1 = f.call(cx, scope, scope, functionArgs);
				finalResult = Context.toString(result1);
				//System.out.println(finalResult);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}finally {
			Context.exit();
		}
		
		// Adding BOM to the result
		if(hasBOM){
			finalResult = testBOMInput[0]+finalResult;
		}
		return finalResult;
	}

	// Show a message to the user
	public void showMessage(String strMsg){
		mCallbacks.issueAlert(strMsg);
		if(!isAutomatic)
			JOptionPane.showMessageDialog(null, strMsg);
		System.out.println(strMsg);
	}

	// Common method to ask a multiple question
	public Integer askConfirmMessage(String strTitle, String strQuestion, String[] msgOptions){
		Object[] options = msgOptions;
		int n = 0;
		n = JOptionPane.showOptionDialog(null,
				strQuestion,
				strTitle,
				JOptionPane.YES_NO_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE,
				null,
				options,
				options[0]);
		return n;
	}

	// Split header and body of a request or response
	private String[] getHeaderAndBody(byte[] fullMessage) throws UnsupportedEncodingException{
		String[] result = {"",""};
		String strFullMessage = "";
		if(fullMessage != null){
			// splitting the message to retrieve the header and the body
			strFullMessage = new String(fullMessage,encoding);
			if(strFullMessage.contains("\r\n\r\n"))
				result = strFullMessage.split("\r\n\r\n",2);
		}
		return result;
	}

	// Read the Content-Type value from the header
	private String findHeaderContentType(String strHeader){
		String contentType="";
		if(!strHeader.equals("")){
			Pattern MY_PATTERN = Pattern.compile("(?im)^content-type:([\\ \\w\\/\\-\\_\\,]*)"); // just in case, it also includes ",_ " 
			Matcher m = MY_PATTERN.matcher(strHeader);
			if (m.find()) {
				contentType = m.group(1);
			}
		}
		return contentType;
	}

	// Check to see if it is a CSS file to protect it from being corrupted
	private boolean isUnprotectedCSSFile(String strHeader, String strBody){
		boolean result = false;
		// Check if it is a CSS file to prevent from being checked as a JS file
		if(!strHeader.equals("") && !strBody.equals("")){
			if(findHeaderContentType(strHeader).toLowerCase().contains("css")){
				String startwithStyleTagRegex = "(?i)^[\\s]*\\<style[\\s\\\\/>]+";
				if(!strBody.matches(startwithStyleTagRegex)){
					result = true; // It does not start with any <style tag
				}
			}
		}
		return result;
	}
	
	// Check to see if it is a HTML or XML file
	private boolean isHtmlXmlFile(String strHeader, String strBody){
		boolean result = false;
		// Check if it is a CSS file to prevent from being checked as a JS file
		if(!strHeader.equals("") && !strBody.equals("")){
			if(findHeaderContentType(strHeader).toLowerCase().contains("html") || findHeaderContentType(strHeader).toLowerCase().contains("xml")){
				result = true;
			}
		}
		return result;
	}
	
	// Check for Byte Order Mark (BOM) character ~ http://www.unicode.org/faq/utf_bom.html#BOM
	// split the text to two sections: [0]=BOM Character,[1]=Text without BOM character
	private String[] splitBOMCharacter(String strInput){
		String[] strResulat = {"",""};
		if (strInput == null)
			return strResulat;

		if(!strInput.equals("")){
			final byte[] byteInput = strInput.getBytes();
			if(byteInput.length>4){
				if ((byteInput[0] == (byte)0xFF) &&
						(byteInput[1] == (byte)0xFE) &&
						(byteInput[2] == (byte)0x00) &&
						(byteInput[3] == (byte)0x00))
				{
					strResulat[0] = new String(BOM.UTF_32_LE.bytes);
					

				}
				else if ((byteInput[0] == (byte)0x00) &&
						(byteInput[1] == (byte)0x00) &&
						(byteInput[2] == (byte)0xFE) &&
						(byteInput[3] == (byte)0xFF))
				{
					strResulat[0]  = new String(BOM.UTF_32_BE.bytes);

				} else				if ((byteInput[0] == (byte)0xEF) &&
						(byteInput[1] == (byte)0xBB) &&
						(byteInput[2] == (byte)0xBF))
				{
					strResulat[0]  = new String(BOM.UTF_8.bytes);

				}else if ((byteInput[0] == (byte)0xFF) &&
						(byteInput[1] == (byte)0xFE))
				{
					strResulat[0]  = new String(BOM.UTF_16_LE.bytes);

				}
				else			if ((byteInput[0] == (byte)0xFE) &&
						(byteInput[1] == (byte)0xFF))
				{
					strResulat[0]  = new String(BOM.UTF_16_BE.bytes);

				}else{

					strResulat[0]  = "";
				}
				strResulat[1] = strInput.substring(strResulat[0].length());
			}else{
				strResulat[1] = strInput; // this text is not important for us!
			}
		}
		return strResulat;
	}
	
	// Check the content type of the response message to be in text-format 
	private boolean isValidContentType(String strHeader, String strBody){
		boolean result = false;
		if(!strHeader.equals("")){

			// 1- Check for a URL/Link usually for ajax queries, we do not want to beautify it if it only contains a URL (normal or relative)
			// Regex From: http://stackoverflow.com/questions/161738/what-is-the-best-regular-expression-to-check-if-a-string-is-a-valid-url
			// I have also added control characters to cover some strange flash requests! 0x00-0x0F and 0x7F ~ http://en.wikipedia.org/wiki/Control_character
			// Hopefully is not vulnerable to ReDos! Not sure!
			String relativeOrNormalURLRegex= "(?im)^(?:[a-z](?:[-a-z0-9\\+\\.])*:(?:\\/\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:])*@)?(?:\\[(?:(?:(?:[0-9a-f]{1,4}:){6}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|::(?:[0-9a-f]{1,4}:){5}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:[0-9a-f]{1,4}:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|v[0-9a-f]+[\\x00-\\x0f\\x7f\\-a-z0-9\\._~!\\$&'\\(\\)\\*\\+,;=:]+)\\]|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}|(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=@])*)(?::[0-9]*)?(?:\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))*)*|\\/(?:(?:(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))+)(?:\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))*)*)?|(?:(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))+)(?:\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))*)*|(?!(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@])))(?:\\?(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@])|[\\x{E000}-\\x{F8FF}\\x{F0000}-\\x{FFFFD}|\\x{100000}-\\x{10FFFD}\\/\\?])*)?(?:\\#(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@])|[\\/\\?])*)?|(?:\\/\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:])*@)?(?:\\[(?:(?:(?:[0-9a-f]{1,4}:){6}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|::(?:[0-9a-f]{1,4}:){5}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:[0-9a-f]{1,4}:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3})|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|v[0-9a-f]+[\\x00-\\x0f\\x7f\\-a-z0-9\\._~!\\$&'\\(\\)\\*\\+,;=:]+)\\]|(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(?:\\.(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}|(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=@])*)(?::[0-9]*)?(?:\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))*)*|\\/(?:(?:(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))+)(?:\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))*)*)?|(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=@])+)(?:\\/(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@]))*)*|(?!(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@])))(?:\\?(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@])|[\\x{E000}-\\x{F8FF}\\x{F0000}-\\x{FFFFD}|\\x{100000}-\\x{10FFFD}\\/\\?])*)?(?:\\#(?:(?:%[0-9a-f][0-9a-f]|[\\x00-\\x0f\\x7f\\-a-z0-9\\._~\\x{A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}\\x{10000}-\\x{1FFFD}\\x{20000}-\\x{2FFFD}\\x{30000}-\\x{3FFFD}\\x{40000}-\\x{4FFFD}\\x{50000}-\\x{5FFFD}\\x{60000}-\\x{6FFFD}\\x{70000}-\\x{7FFFD}\\x{80000}-\\x{8FFFD}\\x{90000}-\\x{9FFFD}\\x{A0000}-\\x{AFFFD}\\x{B0000}-\\x{BFFFD}\\x{C0000}-\\x{CFFFD}\\x{D0000}-\\x{DFFFD}\\x{E1000}-\\x{EFFFD}!\\$&'\\(\\)\\*\\+,;=:@])|[\\/\\?])*)?)$";
			// We do not want to beautify it if it only contains a URL (normal or relative)
			if(strBody.matches(relativeOrNormalURLRegex)){
				result = false; // It should be already false
				return result;
			}

			// 2- Check for the Content-Type value  now!
			String contentType= findHeaderContentType(strHeader);

			// We are only interested in the following types
			// main beautifier function cannot work with a CSS file without having a STYLE tag - a fix needs to be added later
			String[] validTypes = {"text","html","xml","javascript","vml","svg","json","ajax","css"}; 
			for(String item : validTypes){
				if (contentType.toLowerCase().contains(item.toLowerCase())){
					result = true;
					break;
				}
			}
		}
		return result;
	}

	// Check the body of the request to not be a normal POST request
	private boolean isNormalPostMessage(String strBody){
		boolean result = false;
		if(!strBody.equals("")){
			// We are only interested when there is a valid pair
			if((strBody.startsWith("{") && strBody.endsWith("}"))||(strBody.startsWith("<") && strBody.endsWith(">"))||(strBody.startsWith("[") && strBody.endsWith("]"))||(strBody.startsWith("(") && strBody.endsWith(")"))){
				// It seems valid to be beautified as it is not a normal POST message
				result = false;
			}else{
				// It is a normal POST message? even multipart/form-data? 
				result = true;
			}
		}
		return result;
	}
}
