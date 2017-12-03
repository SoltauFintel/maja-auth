package de.mwvb.maja.auth;

import com.github.scribejava.core.oauth.OAuth20Service;

public class LoginData {
	private final OAuth20Service oauth;
	private final String url;
	private final AuthPlugin authPlugin;
	private final boolean rememberMeWanted;
	
	public LoginData(OAuth20Service oauth, String url, AuthPlugin authPlugin, boolean rememberMeWanted) {
		this.oauth = oauth;
		this.url = url;
		this.authPlugin = authPlugin;
		this.rememberMeWanted = rememberMeWanted;
	}
	
	public OAuth20Service getOauth() {
		return oauth;
	}

	public String getUrl() {
		return url;
	}

	public AuthPlugin getAuthPlugin() {
		return authPlugin;
	}

	public boolean isRememberMeWanted() {
		return rememberMeWanted;
	}
}
