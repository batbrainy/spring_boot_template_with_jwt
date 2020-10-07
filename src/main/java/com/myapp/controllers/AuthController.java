package com.myapp.controllers;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.myapp.db.entities.ERole;
import com.myapp.db.entities.Role;
import com.myapp.db.entities.User;
import com.myapp.db.repository.RoleRepository;
import com.myapp.db.repository.UserRepository;
import com.myapp.security.Util;
import com.myapp.security.services.UserDetailsImpl;
import com.myapp.service.LoginService;
import com.myapp.service.MailService;
import com.myapp.service.PasswordService;
import com.myapp.vo.payload.request.ForgotRequest;
import com.myapp.vo.payload.request.LoginRequest;
import com.myapp.vo.payload.request.SignupRequest;
import com.myapp.vo.payload.request.UpdatePasswordRequest;
import com.myapp.vo.payload.response.MessageResponse;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	private static final Logger log = LoggerFactory.getLogger(AuthController.class);
	@Autowired
	private PasswordService passwordService;
	
	@Autowired
	private LoginService loginService;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PasswordEncoder encoder;

	@Autowired
	private MailService mailService;
	
	@PutMapping("/password")
	public ResponseEntity<?> updatePassword(@Valid @RequestBody UpdatePasswordRequest updatePasswordRequest){
		try {
			passwordService.updatePassowrd(updatePasswordRequest);
			return ResponseEntity.accepted().body(true);
		} catch (Exception e) {
			log.error("Error on update password request for " + updatePasswordRequest.getEmail(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
		}
	}
	
	@PostMapping("/forgot")
	public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotRequest forgotRequest){
		try {
			passwordService.forgotPassword(forgotRequest);
			return ResponseEntity.accepted().body(true);
		} catch (Exception e) {
			log.error("Error on forgot password", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
		}
	}

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
		try {
			return ResponseEntity.ok(loginService.login(loginRequest.withServletRequest(httpServletRequest)));
		}
		catch(BadCredentialsException be) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad credentials");
		}
		catch (Exception e) {
			log.error("Error on signin", e);
			return ResponseEntity.badRequest().body("Error occured");
		}
	}
	
	@GetMapping("/me/{username}")
	public ResponseEntity<?> me(@PathVariable String username, @RequestHeader (name="Authorization") String token){
		UserDetailsImpl userDetails = (UserDetailsImpl)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if(userDetails == null) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new MessageResponse("User info not found through auth"));
		}
		Set<ERole> roles = Util.getRoles(userDetails);
		if(roles == null || roles.size() == 0) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new MessageResponse("No role found"));
		}
		//TODO: if role mod or admin can only query others
		if(StringUtils.compare(username, userDetails.getUsername()) == 0 
				|| roles.contains(ERole.ROLE_ADMIN) 
				|| roles.contains(ERole.ROLE_MODERATOR)) {
			return ResponseEntity.ok(userRepository.findByUsername(username).get());
		}
		else {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new MessageResponse("Your role is not authorized to view this resource"));
		}
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if(StringUtils.isAnyBlank(signUpRequest.getUsername(), signUpRequest.getPassword(), signUpRequest.getEmail())){
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: all fields required!"));
		}
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.status(HttpStatus.IM_USED)
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.status(HttpStatus.IM_USED)
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
				signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));
		Set<Role> roles = new HashSet<>();
		Role userRole = roleRepository.findByName(ERole.ROLE_UNCONFIRMED)
				.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
		roles.add(userRole);
		user.setRoles(roles);
		userRepository.save(user);
		try {
			mailService.sendEmail(user.getEmail(), 
					"no-reply@myapp.com",
					"My app - welcome", 
					"<div>"
					+ "<p> </p>"
					+ "<p> Thank you for using my app service. You are now signed up. </p>"
					+ "<p> Your user name is "+user.getUsername()+". </p>"
					
					+ "</div>");
		} catch (IOException e) {
			log.error("Error sending email to " + user.getEmail(), e);
		}
		log.info("User signed up: " + user.getUsername());
		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}
}
