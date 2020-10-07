package com.myapp.security;

import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import com.myapp.db.entities.ERole;
import com.myapp.security.services.UserDetailsImpl;

public final class Util {
	public static boolean checkPermissionHigherOrEqual(ERole role, UserDetailsImpl userDetails) {
		Set<ERole> roles = getRoles(userDetails);
		return roles.parallelStream().anyMatch(x -> x.getIntValue() >= role.getIntValue());
	}

	public static Set<ERole> getRoles(UserDetailsImpl userDetails) {
		return userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.map(item -> ERole.fromString(item))
				.collect(Collectors.toSet());
	}
	
	public static String getClientIP(HttpServletRequest request) {
		try {
		    String xfHeader = request.getHeader("X-Forwarded-For");
		    if (xfHeader == null){
		        return request.getRemoteAddr();
		    }
		    return xfHeader.split(",")[0];
		}
		catch (Exception e) {
			return null;
		}
	}
}
