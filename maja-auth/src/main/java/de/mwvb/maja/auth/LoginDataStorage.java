package de.mwvb.maja.auth;

import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * Universal storage for login data objects, that cannot become too big.
 */
public class LoginDataStorage<LOGINDATA> {
	private final Cache<String, LOGINDATA> storage = // thread-safe and cannot become too big 
			CacheBuilder.newBuilder().initialCapacity(20).maximumSize(1000)
				.expireAfterWrite(5, TimeUnit.MINUTES).build();

	public synchronized void push(String key, LOGINDATA handle) {
		storage.put(key, handle);
	}
	
	public synchronized LOGINDATA pop(String key) {
		LOGINDATA ret = storage.getIfPresent(key);
		if (ret != null) {
			storage.invalidate(key);
		}
		return ret;
	}
}
