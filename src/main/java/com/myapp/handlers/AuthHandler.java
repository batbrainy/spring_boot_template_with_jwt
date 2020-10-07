package com.myapp.handlers;
import java.io.IOException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.myapp.db.entities.ERole;
import com.myapp.db.entities.Role;
import com.myapp.db.entities.User;
import com.myapp.db.repository.RoleRepository;
import com.myapp.db.repository.UserRepository;
import com.myapp.exception.BadRequestException;
import com.myapp.exception.ForbiddenException;
import com.myapp.exception.NotFoundException;
import com.myapp.security.Util;
import com.myapp.security.services.UserDetailsImpl;
import com.myapp.service.LoginService;
import com.myapp.service.MailService;
import com.myapp.service.PasswordService;
import com.myapp.vo.payload.request.ForgotRequest;
import com.myapp.vo.payload.request.LoginRequest;
import com.myapp.vo.payload.request.SignupRequest;
import com.myapp.vo.payload.request.UpdatePasswordRequest;
import com.myapp.vo.payload.request.UpdateRoleRequest;
import com.myapp.vo.payload.response.JwtResponse;

@Component
public class AuthHandler extends BaseHandler {

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
	
	public void updatePassword(UpdatePasswordRequest updatePasswordRequest) {
		passwordService.updatePassowrd(updatePasswordRequest);
	}
	public void forgotPassword(ForgotRequest forgotRequest) {
		passwordService.forgotPassword(forgotRequest);
	}
	
	public JwtResponse login(LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
		return loginService.login(loginRequest.withServletRequest(httpServletRequest));
	}
	
	public void updateUserRole(UpdateRoleRequest updateRoleRequest) {
		userRepository.findByUserName(updateRoleRequest.getUserName()).ifPresent(user ->{
			roleRepository.findByName(updateRoleRequest.getNewRole()).ifPresent(role ->{
				Set<Role> roles = user.getRoles();
				roles.add(role);
				userRepository.save(user);
			});
		});
		
	}
	
	public User getUserInfo(Optional<String> username) {
		
		UserDetailsImpl userDetails = (UserDetailsImpl)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if(userDetails == null) {
			throw new NotFoundException("User info not found");
		}
		String userToFind = username.isPresent() ? username.get() : userDetails.getUsername();
		Set<ERole> roles = Util.getRoles(userDetails);
		//TODO: if role mod or admin can only query others
		if(StringUtils.compare(userToFind, userDetails.getUsername()) == 0 
				|| roles.contains(ERole.ROLE_ADMIN) 
				|| roles.contains(ERole.ROLE_MODERATOR)) {
			return userRepository.findByUserName(userToFind).get();
		}
		else {
			throw new ForbiddenException("Your role is not authorized to view this resource");
		}
	}
	
	public boolean signup(SignupRequest signUpRequest) {
		if(StringUtils.isAnyBlank(signUpRequest.getUsername(), 
				signUpRequest.getPassword(), 
				signUpRequest.getEmail())){
			throw new BadRequestException("Error: all fields required!");
		}
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			throw new BadRequestException("Error: Username is already taken!");
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			throw new BadRequestException("Error: Email is already in use!");
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
				signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));
		HashSet<Role> roles = new HashSet<>();
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
		return true;
	}
}
