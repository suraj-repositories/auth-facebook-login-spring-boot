package com.on11Aug24.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.on11Aug24.entity.User;

public interface UserRepository extends JpaRepository<User, String>{
	
	User findByEmail(String email);
}
