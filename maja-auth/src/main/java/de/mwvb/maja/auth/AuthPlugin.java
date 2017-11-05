package de.mwvb.maja.auth;

import static spark.Spark.before;
import static spark.Spark.halt;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.jetty.http.HttpStatus;
import org.pmw.tinylog.Logger;

import de.mwvb.maja.auth.rememberme.IKnownUser;
import de.mwvb.maja.auth.rememberme.NoOpRememberMeFeature;
import de.mwvb.maja.auth.rememberme.RememberMeFeature;
import de.mwvb.maja.web.Action;
import de.mwvb.maja.web.Template;
import spark.Filter;
import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.Session;

/**
 * Web application plugin for authorization
 */
public class AuthPlugin implements de.mwvb.maja.web.AuthPlugin, Filter {
	public static final String USER_ATTR = "user";
	private static final String LOGGED_IN = "logged_in";
	private static final String LOGGED_IN_YES = "yes";
	private static final String USERID_ATTR = "user_id";
	private final Set<String> notProtected = new HashSet<>();
	private final Authorization authorization;
	private final AuthFeature feature;
	private final RememberMeFeature rememberMe;
	private boolean active = true;

	public AuthPlugin(Authorization authorization, AuthFeature feature) {
		this(authorization, feature, new NoOpRememberMeFeature());
	}

	public AuthPlugin(Authorization authorization, AuthFeature feature, RememberMeFeature rememberMe) {
		this.authorization = authorization;
		this.feature = feature;
		this.feature.init(this);
		this.rememberMe = rememberMe;
	}
	
	@Override
	public void deactivate() {
		active = false;
	}

	@Override
	public void addNotProtected(String path) {
		notProtected.add(path);
	}

	protected boolean isProtected(String uri) {
		for (String begin : notProtected) {
			if (uri.startsWith(begin)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void routes() {
		if (active) {
			before(this);
		}
		
		addNotProtected("/logout");
		Action.get("/logout", new LogoutAction(rememberMe));
		
		feature.routes();
	}

	public static String getUser(Session session) {
		return session.attribute(USER_ATTR);
	}
	
	public static String getUserId(Session session) {
		return session.attribute(USERID_ATTR);
	}

	static void setLoginData(boolean loggedIn, String name, String id, Session session) {
		session.attribute(LOGGED_IN, loggedIn ? LOGGED_IN_YES : null);
		session.attribute(USER_ATTR, name);
		session.attribute(USERID_ATTR, id);
	}
	
	@Override
	public void handle(Request req, Response res) throws Exception {
		String uri = req.uri();
		if (isProtected(uri) && !LOGGED_IN_YES.equals(req.session().attribute(LOGGED_IN))) {
			IKnownUser knownUser = rememberMe.getUserIfKnown(req, res);
			if (knownUser != null) {
				setLoginData(true, knownUser.getUser(), knownUser.getUserId(), req.session());
				return;
			}
			req.session().attribute("uri", uri); // Go back to this page after login
			Map<String, Object> model = new HashMap<>();
			ModelAndView mv = new ModelAndView(model, Action.folder + "login" + Action.suffix);
			halt(HttpStatus.UNAUTHORIZED_401, Template.render(mv));
		}
	}
	
	@Override
	public String login(Request req, Response res, String name, String foreignId, String service, boolean rememberMeWanted) {
		String msg = authorization.check(req, res, name, foreignId, service);
		if (msg != null) {
			return msg;
		}
		
		String longId = service + "#" + foreignId;
		setLoginData(true, name, longId, req.session());
		rememberMe.rememberMe(rememberMeWanted, res, name, longId);
		Logger.debug("Login: " + name + " (" + longId + ")");

		// Redirect zur ursprünglich angewählten Seite
		String uri = req.session().attribute("uri");
		if (uri == null || uri.isEmpty()) {
			uri = "/";
		}
		req.session().removeAttribute("uri");
		res.redirect(uri);
		return "";
	}
}