package com.myapp.vo.payload.request;

import com.myapp.db.entities.ERole;

public class UpdateRoleRequest {
	private String userName;
	private ERole newRole;
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public ERole getNewRole() {
		return newRole;
	}
	public void setNewRole(ERole newRole) {
		this.newRole = newRole;
	}
	
}
