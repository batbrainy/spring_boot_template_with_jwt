package com.myapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;

@SpringBootApplication
@EnableJpaRepositories(basePackages = "com.myapp.*")
@EntityScan("com.myapp.*") 
@ComponentScan(basePackages = { "com.myapp.*" })
public class MyApp {

	public static void main(String[] args) {
		// to parse joda date time
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModule(new JodaModule());
		SpringApplication.run(MyApp.class, args);
	}

}
