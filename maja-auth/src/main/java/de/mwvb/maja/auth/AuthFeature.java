package de.mwvb.maja.auth;

import de.mwvb.maja.web.AuthPlugin;

/**
 * Feature for AuthPlugin
 */
public interface AuthFeature {

	void init(AuthPlugin owner);
	
	void routes();
}
