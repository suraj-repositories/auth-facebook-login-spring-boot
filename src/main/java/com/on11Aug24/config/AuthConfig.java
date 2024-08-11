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
					.oauth2Login(form->form
							.loginPage("/login")
							.defaultSuccessUrl("/login/facebook")
							.failureHandler(new SimpleUrlAuthenticationFailureHandler())
							)
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
