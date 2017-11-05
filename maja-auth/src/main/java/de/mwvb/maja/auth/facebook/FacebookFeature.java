package de.mwvb.maja.auth.facebook;

import de.mwvb.maja.auth.AuthFeature;
import de.mwvb.maja.web.Action;
import de.mwvb.maja.web.AuthPlugin;

/**
 * Add this feature to AuthPlugin to allow the user to use Facebook for authorization.
 */
public class FacebookFeature implements AuthFeature {
	private AuthPlugin authPlugin;
	
	@Override
	public void init(AuthPlugin owner) {
		this.authPlugin = owner;
		System.out.println("init AuthFeature for Facebook");
	}

	@Override
	public void routes() {
		authPlugin.addNotProtected("/login/");
		String callback = "/login/facebook-callback";
		Action.get("/login/facebook", new FacebookLoginAction(authPlugin, callback));
		Action.get(callback, FacebookCallbackAction.class);
	}
}
