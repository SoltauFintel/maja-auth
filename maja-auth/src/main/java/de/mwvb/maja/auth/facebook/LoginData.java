package de.mwvb.maja.auth.facebook;

import com.github.scribejava.core.oauth.OAuth20Service;

import de.mwvb.maja.auth.AuthPlugin;

public class FacebookHandle {
	private final OAuth20Service oauth;
	private final String url;
	private final AuthPlugin authPlugin;
	private final boolean rememberMeWanted;
	
	public FacebookHandle(OAuth20Service oauth, String url, AuthPlugin authPlugin, boolean rememberMeWanted) {
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
