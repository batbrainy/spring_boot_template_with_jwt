package com.myapp.db.entities;

import java.util.EnumSet;

import org.apache.commons.lang3.StringUtils;

public enum ERole {
	ROLE_USER(1),
    ROLE_MODERATOR(3),
    ROLE_UNCONFIRMED(0),
    ROLE_ADMIN(4);
	
	private int intValue;
	
	private ERole(int value) {
		this.intValue = value;
	}
	
	public int getIntValue() {
		return intValue;
	}
	
	public static ERole fromString(String str) {
		if(StringUtils.isBlank(str)) {
			return null;
		}
		for(ERole role : EnumSet.allOf(ERole.class)) {
			if(str.compareToIgnoreCase(role.name()) == 0) {
				return role;
			}
		}
		return null;
	}
	
	@Override
	public String toString() {
		return super.toString();
	}
}
