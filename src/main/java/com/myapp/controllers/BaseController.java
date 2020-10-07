package com.myapp.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class BaseController {
	protected final Logger log = LoggerFactory.getLogger(BaseController.class);
}
