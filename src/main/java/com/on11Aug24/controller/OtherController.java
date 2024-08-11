package com.on11Aug24.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class OtherController {

	@GetMapping("/admin")
	@ResponseBody
	public String adminAccessPage() {
		return "THIS IS ADMIN DASHBOARD";
	}

	@GetMapping("/user")
	@ResponseBody
	public String userAccessPage() {
		return "THIS IS USER DASHBOARD [ADMIN also access this]";
	}
}