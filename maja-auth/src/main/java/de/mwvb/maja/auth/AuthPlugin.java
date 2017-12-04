package de.mwvb.maja.auth;

import static spark.Spark.before;
import static spark.Spark.halt;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.jetty.http.HttpStatus;
import org.pmw.tinylog.Logger;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Module;

import de.mwvb.maja.auth.facebook.FacebookAuthorization;
import de.mwvb.maja.auth.facebook.FacebookFeature;
import de.mwvb.maja.auth.google.GoogleAuthorization;
import de.mwvb.maja.auth.google.GoogleFeature;
import de.mwvb.maja.auth.rememberme.IKnownUser;
import de.mwvb.maja.auth.rememberme.NoOpRememberMeFeature;
import de.mwvb.maja.auth.rememberme.RememberMeFeature;
import de.mwvb.maja.web.Action;
import de.mwvb.maja.web.AppConfig;
import de.mwvb.maja.web.BroadcastListener;
import de.mwvb.maja.web.Broadcaster;
import de.mwvb.maja.web.Plugin;
import de.mwvb.maja.web.Routes;
import de.mwvb.maja.web.Template;
import spark.Filter;
import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.Session;

/**
 * Web application plugin for authorization
 */
public class AuthPlugin implements Plugin, BroadcastListener, Filter {
	public static final String NOT_PROTECTED = "notProtected";
	public static final String USER_ATTR = "user";
	private static final String LOGGED_IN = "logged_in";
	private static final String LOGGED_IN_YES = "yes";
	private static final String USERID_ATTR = "user_id";
	private final Set<String> notProtected = new HashSet<>();
	@Inject
	private AppConfig config;
	@Inject
	private Injector injector;
	@Inject
	private Broadcaster broadcaster;
	@Inject
	private RememberMeFeature rememberMe;
	@Inject
	private Routes routes;
	private Authorization authorization; // set in install()
	private AuthFeature feature; // set in install()
	
	public AuthPlugin() {
		initNotProtected();
	}
	
	protected void initNotProtected() {
		notProtected.add("/rest/_");
		notProtected.add("/favicon.ico");
	}

	@Override
	public Module getModule() {
		return new AbstractModule() {
			@Override
			protected void configure() {
				bind(RememberMeFeature.class).to(getRememberMeClass());
				bind(AuthPlugin.class).toInstance(AuthPlugin.this);
			}
		};
	}
	
	protected Class<? extends RememberMeFeature> getRememberMeClass() {
		return NoOpRememberMeFeature.class;
	}
	
	@Override
	public void prepare() {
		broadcaster.addListener(this);
	}

	/** Handle broadcast during setup */
	@Override
	public void handle(String topic, String data) {
		if (NOT_PROTECTED.equals(topic) && data != null && !data.trim().isEmpty()) {
			addNotProtected(data.trim());
		}
	}
	
	public void addNotProtected(String path) {
		notProtected.add(path);
	}

	@Override
	public void install() {
		feature = getFeature();
		authorization = getAuthorization();
		rememberMe.install();
	}
	
	protected AuthFeature getFeature() {
		if (hasFacebook() && hasGoogle()) {
			return new MultiAuthFeature(getFacebookFeature(), getGoogleFeature());
		} else if (hasFacebook()) {
			return getFacebookFeature();
		} else if (hasGoogle()) {
			return getGoogleFeature();
		} else {
			return null; // AuthPlugin added, but Auth is not active
		}
	}

	private FacebookFeature getFacebookFeature() {
		FacebookFeature facebook = new FacebookFeature();
		injector.injectMembers(facebook);
		return facebook;
	}

	private GoogleFeature getGoogleFeature() {
		GoogleFeature google = new GoogleFeature();
		injector.injectMembers(google);
		return google;
	}

	protected Authorization getAuthorization() {
		if (hasFacebook() && hasGoogle()) {
			return new AuthorizationDispatcher(new FacebookAuthorization(), new GoogleAuthorization());
		} else if (hasFacebook()) {
			return new FacebookAuthorization();
		} else if (hasGoogle()) {
			return new GoogleAuthorization();
		} else {
			return null; // AuthPlugin added, but Auth is not active
		}
	}

	private boolean hasFacebook() {
		return config.hasFilledKey("facebook.key");
	}

	private boolean hasGoogle() {
		return config.hasFilledKey("google.key");
	}

	@Override
	public void routes() {
		if (feature != null) {
			before(this);
		
			notProtected.add("/logout");
			routes._get("/logout", LogoutAction.class);
			
			feature.routes();
		}
	}

	@Override
	public void printInfo() {
	}

	public String getUser(Session session) {
		return session.attribute(USER_ATTR);
	}
	
	public static String getUserId(Session session) {
		return session.attribute(USERID_ATTR);
	}

	public void setLoginData(boolean loggedIn, String name, String id, Session session) {
		session.attribute(LOGGED_IN, loggedIn ? LOGGED_IN_YES : null);
		session.attribute(USER_ATTR, name);
		session.attribute(USERID_ATTR, id);
	}
	
	/** Handle request during program execution */
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
	
	protected boolean isProtected(String uri) {
		for (String begin : notProtected) {
			if (uri.startsWith(begin)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Called by the callback action to login the user to the Maja system.
	 * 
	 * @param req Request
	 * @param res Response
	 * @param name user name from the foreign auth service
	 * @param foreignId user id from the foreign auth service
	 * @param service id of the auth service
	 * @param rememberMe true if the remember service shall store the login, false if the remember service shall delete the login
	 * @return usually "" because a redirect to another page will be executed
	 */
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