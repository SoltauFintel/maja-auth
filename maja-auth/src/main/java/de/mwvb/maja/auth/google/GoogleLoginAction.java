package de.mwvb.maja.auth.google;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.inject.Inject;

import de.mwvb.maja.auth.AuthPlugin;
import de.mwvb.maja.auth.LoginData;
import de.mwvb.maja.auth.LoginDataStorage;
import de.mwvb.maja.web.ActionBase;
import de.mwvb.maja.web.AppConfig;

public class GoogleLoginAction extends ActionBase {
	private static final LoginDataStorage<LoginData> loginDataStorage = new LoginDataStorage<>();
	@Inject
	private AuthPlugin authPlugin;
	@Inject
	private AppConfig config;
	
	@Override
	public String run() {
		boolean remember = !"0".equals(req.queryParams("remember"));
		String secretState = config.get("google.state") + new Random().nextInt(999999);
		String callback = config.get("host") + GoogleFeature.CALLBACK;
		OAuth20Service oauth = new ServiceBuilder(config.get("google.key"))
				.apiSecret(config.get("google.secret"))
				.scope("email")
				.state(secretState)
				.callback(callback)
				.build(GoogleApi20.instance());
        // pass access_type=offline to get refresh token
        // https://developers.google.com/identity/protocols/OAuth2WebServer#preparing-to-start-the-oauth-20-flow
        final Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("access_type", "offline");
        // force to reget refresh token (if usera are asked not the first time)
        additionalParams.put("prompt", "consent");
		String url = oauth.getAuthorizationUrl(additionalParams);
		String url2 = config.get("google.url");
		loginDataStorage.push(secretState, new LoginData(oauth, url2, authPlugin, remember));
		res.redirect(url);
		return "";
	}
	
	public static LoginData pop(String key) {
		return loginDataStorage.pop(key);
	}
}
