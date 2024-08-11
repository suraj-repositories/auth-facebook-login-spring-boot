package com.on11Aug24.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.on11Aug24.entity.User;
import com.on11Aug24.repository.UserRepository;
import com.on11Aug24.service.UserService;

@Service
public class UserServiceImpl implements UserService{

	@Autowired
	private UserRepository repository;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Override
	public List<User> getAllUsers() {
		return repository.findAll();
	}

	@Override
	public User getUserById(String id) {
		return repository.findById(id).orElseThrow(()-> new RuntimeException("User not found!!"));
	}

	@Override
	public User saveUser(User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return repository.save(user);
	}

	@Override
	public User getUserByEmail(String email) {
		return repository.findByEmail(email);
	}

	

}
