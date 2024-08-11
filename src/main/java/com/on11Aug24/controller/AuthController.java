package com.on11Aug24.controller;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.on11Aug24.entity.User;
import com.on11Aug24.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller()
public class AuthController {

	@Autowired
	private UserService service;

	@Autowired
	private PasswordEncoder passwordEncoder;

	private Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

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

	@GetMapping("/login")
	public String loginPage(Authentication authentication) {
		if (authentication != null) {
			return "redirect:/";
		}
		return "login";
	}

	@PostMapping
	public String doLogin(@RequestParam("email") String email, @RequestParam("password") String password, Model model) {
		User user = service.getUserByEmail(email);

		if (user == null) {
			model.addAttribute("error", "Invalid email or password!");
			return "Login";
		} else if (!passwordEncoder.matches(password, user.getPassword())) {
			model.addAttribute("error", "Invalid email or password!");
			return "Login";
		}

		SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null,
				Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole()))));

		return "redirect:/";
	}

	@GetMapping("/signup")
	public String signupPage(Model model, Authentication authentication) {
		if (authentication != null) {
			return "redirect:/";
		}
		model.addAttribute("user", new User());
		return "signup";
	}

	@PostMapping("/signup")
	public String signup(User user, Authentication authentication) {
		if (user != null) {
			if (service.getUserByEmail(user.getEmail()) != null) {
				return "redirect:/signup";
			}
			user.setRole("USER");
			service.saveUser(user);
			return "redirect:/login";
		}

		return "redirect:/signup";
	}

	@GetMapping("/welcome")
	public String welcom() {
		return "redirect:/";
	}

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

}
