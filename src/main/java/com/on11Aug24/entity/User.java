package com.on11Aug24.entity;

import java.time.LocalDate;

import org.hibernate.annotations.UuidGenerator;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(value = Include.NON_DEFAULT)
@Table(name = "users")
public class User {
	
	@Id
	@UuidGenerator
	private String id;
	private String name;
	private String email;
	private LocalDate dob;	
	
	@Column(nullable = true)
	private String picture;
	
	private String password;
	@Transient
	private String confirmPassword;
	
	private String role;
}
