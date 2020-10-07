package com.myapp.controllers;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.myapp.db.entities.User;
import com.myapp.handlers.AuthHandler;
import com.myapp.vo.payload.request.ForgotRequest;
import com.myapp.vo.payload.request.LoginRequest;
import com.myapp.vo.payload.request.SignupRequest;
import com.myapp.vo.payload.request.UpdatePasswordRequest;
import com.myapp.vo.payload.request.UpdateRoleRequest;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	private static final Logger log = LoggerFactory.getLogger(AuthController.class);
	
	
	@Autowired
	private AuthHandler authHandler;
	
	@PutMapping("/password")
	@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN') ")
	public ResponseEntity<?> updatePassword(@Valid @RequestBody UpdatePasswordRequest updatePasswordRequest){
		try {
			authHandler.updatePassword(updatePasswordRequest);
			return ResponseEntity.accepted().build();
		} catch (Exception e) {
			log.error("Error on update password request for " + updatePasswordRequest.getEmail(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
		}
	}
	
	@PostMapping("/forgot")
	public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotRequest forgotRequest){
		try {
			authHandler.forgotPassword(forgotRequest);
			return ResponseEntity.accepted().body(true);
		} catch (Exception e) {
			log.error("Error on forgot password", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
		}
	}

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
		try {
			return ResponseEntity.ok(authHandler.login(loginRequest, httpServletRequest));
		}
		catch(BadCredentialsException be) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad credentials");
		}
		catch (Exception e) {
			log.error("Error on signin", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error occured while signing in");
		}
	}
	
	@PutMapping("/role")
	@PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN') ")
	public ResponseEntity<?> updateRoleForUser(@Valid @RequestBody UpdateRoleRequest updateRoleRequest, 
			HttpServletRequest httpServletRequest) {
			authHandler.updateUserRole(updateRoleRequest);
			return ResponseEntity.ok().build();
	}

	@GetMapping(value = {"/user"})
	@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN') ")
	public ResponseEntity<?> me(@RequestParam Optional<String> username){
		User u = authHandler.getUserInfo(username);
		return ResponseEntity.ok(u);
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if(authHandler.signup(signUpRequest)) {
			return ResponseEntity.ok("User signedup successfully: " + signUpRequest.getUsername());
		}
		else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error occured while signup");
		}
	}
}
