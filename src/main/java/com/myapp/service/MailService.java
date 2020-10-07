package com.myapp.service;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.myapp.config.SendgridConfig;
import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;

@Service
public class MailService {
	private static final Logger logger = LoggerFactory.getLogger(MailService.class);


	@Autowired
	private SendgridConfig sendgridConfig;
	
	public void sendEmail(String emailTo, String emailFrom, String subject, String messageContent) throws IOException {
		   Email from = new Email(emailFrom);
	       Email to = new Email(emailTo); 

	       Content content = new Content("text/html", messageContent);

	       Mail mail = new Mail(from, subject, to, content);

	       SendGrid sg = new SendGrid(sendgridConfig.getKey());
	       Request request = new Request();

	       request.setMethod(Method.POST);
	       request.setEndpoint("mail/send");
	       request.setBody(mail.build());

	       Response response = sg.api(request);
	       logger.debug(String.format("Sent email with subject: %s, status code %d", subject, response.getStatusCode()));
	}
}
