package de.mwvb.maja.auth;

import org.pmw.tinylog.Logger;

import com.google.inject.Inject;

import de.mwvb.maja.auth.rememberme.RememberMeFeature;
import de.mwvb.maja.web.ActionBase;
import spark.Session;

public class LogoutAction extends ActionBase {
	@Inject
	private RememberMeFeature rememberMe;
	@Inject
	private AuthPlugin authPlugin;
	
	@Override
	public String run() {
		Session session = req.session();
		String userId = getUserId();
		if (userId != null) {
			Logger.debug("Logout: " + authPlugin.getUser(session) + " (" + userId + ")");
		}
		rememberMe.forget(res, userId);
		authPlugin.setLoginData(false, null, null, session);
		
		res.redirect("/");
		return "";
	}
}
