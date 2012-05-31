package burp.JSBeautifier;

public class CurrentState {
	private static int beautifierState; // 0 = Disabled (Default) , 1 = Enabled in scope
	
	public CurrentState(int beautifierState) {
		super();
		setBeautifierState(beautifierState);
	}

	public synchronized static int getBeautifierState() {
		return beautifierState;
	}

	public synchronized static void setBeautifierState(int newState) {
		beautifierState = newState;
	}

}
