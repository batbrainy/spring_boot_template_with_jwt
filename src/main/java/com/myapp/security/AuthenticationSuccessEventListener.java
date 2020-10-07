package com.myapp.security;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import com.myapp.security.services.UserDetailsImpl;

@Component
public class AuthenticationSuccessEventListener 
  implements ApplicationListener<AuthenticationSuccessEvent> {
 
    public void onApplicationEvent(AuthenticationSuccessEvent e) {
    	// do something with the user if needed
    	UserDetailsImpl user = (UserDetailsImpl) 
          e.getAuthentication().getPrincipal();
    }
}