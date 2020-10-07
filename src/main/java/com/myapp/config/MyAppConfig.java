package com.myapp.config;

import java.util.HashSet;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "myapp")
public class MyAppConfig {
	private HashSet<String> corsAllowIps = new HashSet<String>();
	
	public HashSet<String> getCorsAllowIps() {
		return corsAllowIps;
	}

	public void setCorsAllowIps(HashSet<String> corsAllowIps) {
		this.corsAllowIps = corsAllowIps;
	}
}
