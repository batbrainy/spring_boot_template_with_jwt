# spring_boot_template_with_jwt
Template project with basic implementation to use JWTs and some exception handling to start with

## Features
Allows you to start a project with
- JWT tokens
- Sign in / sign up / forgot & update password apis
- User roles
- Basic security configurations
- Exception handling
- Sendgrid config to send emails
- Actuator, management endpoints
- Slf4j logging

### Things you would need to fix/update
- Data source - Currently the template project uses H2 db on a disk location. Update the source to your liking
- Security configs in `WebSecurityConfig.java`
- Sendgrid API key in `application yml` if you would like to send emails
- Cors settings in `application.yml`
- App port in `application.yml`
- jwt secret in `application.yml`
- Actuator config in `application.yml`
- Logging config in `application.yml`
