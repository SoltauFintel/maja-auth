package de.mwvb.maja.auth.google;

import de.mwvb.maja.auth.AuthFeature;
import de.mwvb.maja.web.Action;
import de.mwvb.maja.web.AuthPlugin;

public class GoogleFeature implements AuthFeature {
	private AuthPlugin authPlugin;
	
	@Override
	public void init(AuthPlugin owner) {
		this.authPlugin = owner;
		System.out.println("init AuthFeature for Google");
	}

	@Override
	public void routes() {
		authPlugin.addNotProtected("/login/");
		authPlugin.addNotProtected("/google/"); // XXX raus
		String callback = "/google/callback"; // XXX ändern
		Action.get("/login/google", new GoogleLoginAction(authPlugin, callback));
		Action.get(callback, GoogleCallbackAction.class);
	}
}
