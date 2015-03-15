# This project has been moved: https://github.com/irsdl/BurpSuiteJSBeautifier #

**Using the application:**

  1. Download the zip file and extract it in root of the Burp Suite folder. Now, you should have a folder with three jar files and a batch file outside of this folder.
  1. Use "beautifier.bat" to run the Burp Suite application. In this file, "burpsuite\_pro.jar" is the name of your Burp Suite jar file. You can also change the Java allocated memory if you experienced any problem. Or, run it via command line directly:
java -Xmx512m -classpath burpsuite\_pro.jar;./beautifier/beautifier.jar;./beautifier/js.jar;./beautifier/rsyntaxtextarea.jar burp.StartBurp
  1. Now if you right click on a request or response, you should be able to see these options: "Beautify This!" and "Beautify All Responses in Scope" (the automated one only works in the "proxy" section to prevent from any performance issue)


**Reporting the issues:**

Issues in this legacy extensions will not be fixed as there is a new version available: https://github.com/irsdl/BurpSuiteJSBeautifier

**Tested on:**

This extension has been tested on Burp Suite Pro v1.4.07 with Java v7u4