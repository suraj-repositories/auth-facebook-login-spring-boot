package com.on11Aug24.service;

import java.util.List;

import com.on11Aug24.entity.User;

public interface UserService {
	
	List<User> getAllUsers();
	
	User getUserById(String id);
	
	User saveUser(User user);
	 
	User getUserByEmail(String email);
	
	
}
