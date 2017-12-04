package de.mwvb.maja.auth.google;

import com.google.inject.Inject;

import de.mwvb.maja.auth.AuthFeature;
import de.mwvb.maja.auth.AuthPlugin;
import de.mwvb.maja.web.Routes;

public class GoogleFeature implements AuthFeature {
	public static final String CALLBACK = "/login/google-callback"; // XXX ändern
	@Inject
	private AuthPlugin authPlugin;
	@Inject
	private Routes routes;
	
	@Override
	public void routes() {
		authPlugin.addNotProtected("/login/");
		routes._get("/login/google", GoogleLoginAction.class);
		routes._get(CALLBACK, GoogleCallbackAction.class);
	}
}
