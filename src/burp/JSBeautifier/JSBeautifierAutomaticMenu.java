package burp.JSBeautifier;

import burp.*;


public class JSBeautifierAutomaticMenu implements burp.IMenuItemHandler{
	private burp.IBurpExtenderCallbacks mCallbacks;
	
	public JSBeautifierAutomaticMenu(burp.IBurpExtenderCallbacks callbacks, CurrentState currentState){
		super();
		mCallbacks = callbacks;
		System.out.println("Beautifier automatic menu item has been loaded!");
	}

	public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo)
	{
		// Loading the beautifier functions
		JSBeautifierFunctions jsBeautifierFunctions = new JSBeautifierFunctions(mCallbacks);
		
		switch(CurrentState.getBeautifierState()){
		case 0:
			CurrentState.setBeautifierState(1);
			jsBeautifierFunctions.showMessage("Automatic beautifying has been enabled in your scope.");
			break;
		case 1:
			CurrentState.setBeautifierState(0);
			jsBeautifierFunctions.showMessage("Automatic beautifying has been disabled.");
			break;
		}
	}

}
