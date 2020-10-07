package com.myapp.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;


@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {
	private final Logger log = LoggerFactory.getLogger(RestExceptionHandler.class);
	@ExceptionHandler(value = { BadRequestException.class, IllegalArgumentException.class })
	protected ResponseEntity<?> handleBadRequest(RuntimeException ex, WebRequest request) {
		log.error(ex.getMessage(), ex);
		return ResponseEntity.badRequest().body(ex.getMessage());
	}
	
	@ExceptionHandler(value = { InternalServerErrorException.class })
	protected ResponseEntity<?> handleInternalServerError(RuntimeException ex, WebRequest request) {
		log.error(ex.getMessage(), ex);
		String bodyOfResponse = ex.getMessage();
		return handleExceptionInternal(ex, bodyOfResponse, new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR, request);
	}
	
	@ExceptionHandler(value = { NotFoundException.class })
	protected ResponseEntity<?> handleNotFoundError(RuntimeException ex, WebRequest request) {
		log.error(ex.getMessage(), ex);
		String bodyOfResponse = ex.getMessage();
		return handleExceptionInternal(ex, bodyOfResponse, new HttpHeaders(), HttpStatus.NOT_FOUND, request);
	}
	
	@ExceptionHandler(value = { ForbiddenException.class })
	protected ResponseEntity<?> handleForbiddenError(RuntimeException ex, WebRequest request) {
		log.error(ex.getMessage(), ex);
		String bodyOfResponse = ex.getMessage();
		return handleExceptionInternal(ex, bodyOfResponse, new HttpHeaders(), HttpStatus.FORBIDDEN, request);
	}
}
