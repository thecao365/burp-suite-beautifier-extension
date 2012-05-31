package burp;
import java.net.URL;

import burp.JSBeautifier.*;

public class BurpExtender 
{
	public burp.IBurpExtenderCallbacks mCallbacks; // I will use this to keep the callbacks
	private burp.JSBeautifier.CurrentState currentState = new CurrentState(0);
	// Create Menu Items
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		System.out.println(Version.getVersion());
		mCallbacks = callbacks;
		mCallbacks.registerMenuItem("Beautify This!", new JSBeautifierManualMenu(mCallbacks));
		mCallbacks.registerMenuItem("Beautify All Responses in Scope!", new JSBeautifierAutomaticMenu(mCallbacks,currentState));
	}


	public void processHttpMessage(
			String toolName, 
			boolean messageIsRequest, 
			IHttpRequestResponse messageInfo)
	{  

		// Loading automatic beautifier
		if (toolName == "proxy" && !messageIsRequest  && CurrentState.getBeautifierState() == 1){
			try
			{
				URL uUrl = messageInfo.getUrl();
				if (mCallbacks.isInScope(uUrl))
				{
					IHttpRequestResponse[] newMessageInfo = new IHttpRequestResponse[1];
					newMessageInfo[0] = messageInfo;
					// Loading the beautifier functions
					JSBeautifierFunctions jsBeautifierFunctions = new JSBeautifierFunctions(mCallbacks);
					jsBeautifierFunctions.beautifyIt(newMessageInfo,true); // Automatic Mode

				}
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}

	}
}

