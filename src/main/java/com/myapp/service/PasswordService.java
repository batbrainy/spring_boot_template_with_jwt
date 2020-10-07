package com.myapp.service;

import javax.transaction.Transactional;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.myapp.db.entities.User;
import com.myapp.db.repository.UserRepository;
import com.myapp.vo.payload.request.ForgotRequest;
import com.myapp.vo.payload.request.UpdatePasswordRequest;

import javassist.NotFoundException;

@Service
public class PasswordService {
	private static final Logger logger = LoggerFactory.getLogger(PasswordService.class);
	@Autowired
	private PasswordEncoder encoder;
	@Autowired
	private MailService mailService;

	@Autowired
	private UserRepository userRepository;
	
	@Transactional
	public boolean updatePassowrd(UpdatePasswordRequest updatePasswordRequest) {
		try {
			if(userRepository.existsByEmail(updatePasswordRequest.getEmail())) {
				User user = userRepository.findByEmail(updatePasswordRequest.getEmail()).get();
				user.setPassword(encoder.encode(updatePasswordRequest.getPassword()));
				changePassword(user);
				mailService.sendEmail(user.getEmail(), 
						"no-reply@myapp.com",
						"My App - password update confirmation", 
						String.format("Dear %s,</p>"
								+ "Thank you for using finder service.</p>"
								+ "Your password has been successfully updated</p>"
								+ "</p>"
								+ "-Finder service</p>", user.getUsername()));
				return true;
			}
			throw new NotFoundException("User not found by email: " + updatePasswordRequest.getEmail());
		}
		catch (Exception e) {
			logger.error("Error occured while updating password", e);
		}
		return false;
	}
	
	@Transactional
	public boolean forgotPassword(ForgotRequest forgotRequest) {
		try {
			if(userRepository.existsByEmail(forgotRequest.getEmail())) {
				// if exists reset password to random str
				String random = RandomStringUtils.random(10, true, true);
				User user = userRepository.findByEmail(forgotRequest.getEmail()).get();
				user.setPassword(encoder.encode(random));
				changePassword(user);
				// send email
				mailService.sendEmail(user.getEmail(),
						"no-reply@myapp.com",
						"Finder service - password reset confirmation",
						String.format("Dear %s,\n"
						+ "Thank you for using finder service.\n"
						+ "Your password has been successfully reset to: %s\n"
						+ "Please change it next time you login\n"
						+ "\n"
						+ "-Finder service\n", user.getUsername(), random));
			}
			else {
				throw new NotFoundException("Specified email not found");
			}
		}
		catch (NotFoundException e) {
			logger.error("Specified email was not found - no password reset" , e);
		}
		catch (Exception e) {
			logger.error("Unknown error occured while trying to send email" , e);
		}
		return false;
	}
	
	@Transactional
	public boolean changePassword(User user) throws NotFoundException {
		try {
			if(userRepository.existsByEmail(user.getEmail())) {
				userRepository.save(user);
			}
			else {
				throw new NotFoundException("Specified email not found");
			}
		}
		catch (NotFoundException e) {
			throw e;
		}
		catch (Exception e) {
			// TODO: handle exception
		}
		return false;
	}
}
