package com.myapp.vo.payload.request;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class LoginRequest {
	@NotBlank
	private String username;

	@NotBlank
	private String password;
	
	@JsonIgnore
	private HttpServletRequest httpServletRequest;
	
	public HttpServletRequest getServletRequest() {
		return httpServletRequest;
	}
	public LoginRequest withServletRequest(HttpServletRequest httpServletRequest) {
		this.httpServletRequest = httpServletRequest;
		return this;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
