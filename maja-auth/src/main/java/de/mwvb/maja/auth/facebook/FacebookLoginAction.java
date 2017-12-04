package de.mwvb.maja.auth.facebook;

import java.util.Random;

import com.github.scribejava.apis.FacebookApi;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.inject.Inject;

import de.mwvb.maja.auth.AuthPlugin;
import de.mwvb.maja.auth.LoginData;
import de.mwvb.maja.auth.LoginDataStorage;
import de.mwvb.maja.web.ActionBase;
import de.mwvb.maja.web.AppConfig;

/**
 * Asks Facebook for authorization
 * 
 * <p>Can have URL argument "remember=0" if it's not wanted that the login is remembered.</p>
 */
public class FacebookLoginAction extends ActionBase {
	private static final LoginDataStorage<LoginData> loginDataStorage = new LoginDataStorage<>();
	@Inject
	private AuthPlugin authPlugin;
	@Inject
	private AppConfig config;
	
	@Override
	public String run() {
		boolean remember = !"0".equals(req.queryParams("remember"));
		String secretState = config.get("facebook.state") + new Random().nextInt(999999);
		String callback = config.get("host") + FacebookFeature.CALLBACK;
		OAuth20Service oauth = new ServiceBuilder(config.get("facebook.key"))
				//v4: .apiKey(config.get("facebook.key"))
				.apiSecret(config.get("facebook.secret"))
				.state(secretState)
				.callback(callback)
				.build(FacebookApi.instance());
		String facebookUrl = config.get("facebook.url");
		String url = oauth.getAuthorizationUrl();
		loginDataStorage.push(secretState, new LoginData(oauth, facebookUrl, authPlugin, remember));
		res.redirect(url);
		return "";
	}
	
	public static LoginData pop(String key) {
		return loginDataStorage.pop(key);
	}
}
