package com.myapp.service;

import java.util.List;
import java.util.stream.Collectors;
import javax.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.myapp.security.Util;
import com.myapp.security.jwt.JwtUtils;
import com.myapp.security.services.UserDetailsImpl;
import com.myapp.vo.payload.request.LoginRequest;
import com.myapp.vo.payload.response.JwtResponse;

@Service
@Transactional
public class LoginService {
	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	private LoginAttemptService loginAttemptService;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	public JwtResponse login(LoginRequest loginRequest) {
		try {
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

			SecurityContextHolder.getContext().setAuthentication(authentication);
			String jwt = jwtUtils.generateJwtToken(authentication);

			UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
			List<String> roles = userDetails.getAuthorities().stream()
					.map(item -> item.getAuthority())
					.collect(Collectors.toList());
			loginAttemptService.loginSucceeded(loginRequest.getUsername());
			loginAttemptService.loginSucceeded(Util.getClientIP(loginRequest.getServletRequest()));

			return new JwtResponse(jwt, 
					userDetails.getId(), 
					userDetails.getUsername(), 
					userDetails.getEmail(), 
					roles);
		}
		catch(BadCredentialsException be) {
			// add user name and ip to failed list
			loginAttemptService.loginFailed(loginRequest.getUsername());
			loginAttemptService.loginFailed(Util.getClientIP(loginRequest.getServletRequest()));
			throw be;
		}
		catch (Exception e) {
			throw e;
		}
	}

}
