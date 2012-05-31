package burp.JSBeautifier;

import burp.IHttpRequestResponse;

public class JSBeautifierManualMenu implements burp.IMenuItemHandler{
	private burp.IBurpExtenderCallbacks mCallbacks;
	
	
	public JSBeautifierManualMenu(burp.IBurpExtenderCallbacks callbacks){
		super();
		mCallbacks = callbacks;
		System.out.println("Beautifier manual menu item has been loaded!");
	}
	

	public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo)
	{
		// Loading the beautifier functions
		JSBeautifierFunctions jsBeautifierFunctions = new JSBeautifierFunctions(mCallbacks);
		
		jsBeautifierFunctions.beautifyIt(messageInfo,false); // Manual mode
	}
	
	
}
