package com.myapp.security;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;


@Component
public class AuthenticationFailureListener 
  implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {
 
	/**
	 * Implement if needed
	 */
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent e) {
    }
}