package com.on11Aug24.service.security;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.on11Aug24.entity.User;
import com.on11Aug24.repository.UserRepository;

@Service
public class CustomUserDetailService implements UserDetailsService {

	@Autowired
	private UserRepository repository;
	
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
	
		User user = repository.findByEmail(email);
		if(user != null) {
			return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(),
												Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole())));
		}
		throw new RuntimeException("Invalid username or password!!");
	}

}
