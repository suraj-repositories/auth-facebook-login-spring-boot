# auth-facebook-login-spring-boot
Login with facebook basic implementation using spring boot



## Steps - 

- Step 1 : First you need a simple login system - I suggest you to take reference from [Role based login](https://github.com/suraj-repositories/auth-spring-security-3)

- Step 2 : Add dependency for oauth2client and spring security on your project 

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
	     
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
		
<dependency>
	<groupId>org.thymeleaf.extras</groupId>
	<artifactId>thymeleaf-extras-springsecurity6</artifactId>
</dependency>

```


- Step 3 : Now you need to create credentials on facebook app
    - go to [developers.facebook.com](https://developers.facebook.com/) -> my apps
    - create new app -> fill details and create an app
        - on `use cases` choose `Authenticate and request data from users with Facebook Login` 
        - on `app detail` fill the app name and your email from which you manage this login system
        - under `review` create app
        - after creating app you will be redirected to dashboard page
    - Under `use cases` on `Authentication and account creation` click on customize
        - Under the permissions add the `email` to allow emails permission from `actions` column
        - Under settings on `Valid OAuth Redirect URIs` fill the redirect path 
            eg. `https://www.example.com/auth/facebook/callback`, but if you are using localhost for practice leave this field empty
        - Under the `quickstart` click on `web` 
            - on `Tell Us about Your Website` fill your website url example - `http://localhost:8080` or `https://www.example.com`. (this field is important and required telling the facebook this website is allowed from my side to use this facebook app)
            - click on save
            - leave others empty
    - On the left sidebar go to `App Settings` -> `basic` 
        - here you can find the `App ID` which is `FACEBOOK CLIENT ID`
        - and `App secret` which is your `FACEBOOK CLIENT SECRET`
    - You need to paste the client id and client-secret into your application.yml file (you need to create application.yml file as the same path on application.properties like : `/auth-spring-security-3/src/main/resources/application.yml`)
    
    
```bash
baseUrl: http://localhost:8080

spring:
  security:
    oauth2:
      client:
        registration:
          facebook:
            client-id: 504109708760691
            client-secret: ad3c9f885c962fa31cc3b28662b9a425
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            # or  both are same
            # redirect-uri: "{baseUrl}/login/oauth2/code/facebook"
            scope: email,public_profile
            client-name: Facebook
            authorization-grant-type: authorization_code
        provider:
          facebook:
            authorization-uri: https://www.facebook.com/v11.0/dialog/oauth
            token-uri: https://graph.facebook.com/v11.0/oauth/access_token
            user-info-uri: https://graph.facebook.com/me?fields=id,name,email,picture
            user-name-attribute: id

```

- Step 4 : you need to configure the oauth2client for facebook login : 

```java
package com.on11Aug24.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

@Configuration
@EnableWebSecurity
public class AuthConfig {
	
	@Autowired
	private UserDetailsService detailsService;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

		httpSecurity.csrf(Customizer.withDefaults())
                    .authorizeHttpRequests(request -> request
						.requestMatchers("/admin/**")
						.hasRole("ADMIN")
						.requestMatchers("/user/**")
						.hasAnyRole("USER", "ADMIN")
						.requestMatchers("/**")
						.permitAll()
						.anyRequest()
						.authenticated())
						.formLogin(form -> form
						.loginPage("/login")
						.loginProcessingUrl("/login")
						.usernameParameter("email")
						.passwordParameter("password")
						.defaultSuccessUrl("/")
						.permitAll())
                    .oauth2Login(form -> form
						.loginPage("/login")
						.defaultSuccessUrl("/login/facebook")        // we can create the custom controller for that URL
						.failureHandler(new SimpleUrlAuthenticationFailureHandler()))
                    .logout(logout -> logout
						.logoutSuccessUrl("/login?logout")
						.permitAll()
				);
	
		return httpSecurity.build();
	}

    @Bean
    static PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(detailsService).passwordEncoder(passwordEncoder());
	}
	
}

```

- Step 5 : On your facebook login page you can use the given link to redirect to the facebook official login page

```html
	<a th:href="@{/oauth2/authorization/facebook}">Login with Facebook</a>
```


- Step 6 : the next step is to create controller methods to handle facebook login : 

```java
@GetMapping("/")
public String home(Model model, Authentication authentication,  HttpServletRequest request, HttpServletResponse response) {
	
	if (authentication != null) {
		User user = service.getUserByEmail(authentication.getName());
		if (user == null) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (auth != null) {
				new SecurityContextLogoutHandler().logout(request, response, auth);
			}
		}
		model.addAttribute("user", user);
	}
	return "welcome";
}

```

```java
@SuppressWarnings("unchecked")
@GetMapping("/login/facebook")
public String loginWithFacebook(OAuth2AuthenticationToken auth) {

	try {
		Map<String, Object> attributes = auth.getPrincipal().getAttributes();

		String name = (String) attributes.get("name");
		String email = (String) attributes.get("email");
		
		Map<String, Object> pictureMap = (Map<String, Object>) attributes.get("picture");	// this is basic way use more efficient way for providing this type-safty
		Map<String, Object> dataMap = (Map<String, Object>) pictureMap.get("data");			// i use this syntax because i want to keep it simple	
		String picture = (String) dataMap.get("url");
	
		LOGGER.info("{} - {} - {}", name, email, picture);

		User user = service.getUserByEmail(email);
		if (user == null) {
			String pass = UUID.randomUUID().toString();
			User createdUser = User.builder().name(name).email(email).picture(picture).id(null).password(pass).confirmPassword(pass)
					.dob(null).role("USER").build();
			user = service.saveUser(createdUser);
		}
		
		Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole() )));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
	} catch (Exception e) {
		LOGGER.error("Authentication error while doing login : " + e.getMessage());
		return "redirect:/login";
	}

	return "redirect:/";
}

```

### File where i made changes 

- all files in src\main\java\com\on11Aug2024
- all files in src\main\resources\com\on11Aug2024
- src\main\resources\application.properties
- src\main\resources\application.yml
- pom.xml

### Need to make sure

- make sure to fit all the config details carefully like client-id, client-secret, redirect-url, base-url in `src\main\resources\application.yml` file
- never forget to create database with the given name if you are using this example

<br />
<br />
<p align="center">⭐️ Star my repositories if you find it helpful.</p>
<br />