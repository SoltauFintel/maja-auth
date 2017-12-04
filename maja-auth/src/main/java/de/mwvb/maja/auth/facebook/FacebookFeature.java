package de.mwvb.maja.auth.facebook;

import com.google.inject.Inject;

import de.mwvb.maja.auth.AuthFeature;
import de.mwvb.maja.auth.AuthPlugin;
import de.mwvb.maja.web.Routes;

/**
 * Add this feature to AuthPlugin to allow the user to use Facebook for authorization.
 */
public class FacebookFeature implements AuthFeature {
	public static final String CALLBACK = "/login/facebook-callback";
	@Inject
	private AuthPlugin authPlugin;
	@Inject
	private Routes routes;
	
	@Override
	public void routes() {
		authPlugin.addNotProtected("/login/");
		routes._get("/login/facebook", FacebookLoginAction.class);
		routes._get(CALLBACK, FacebookCallbackAction.class);
	}
}
