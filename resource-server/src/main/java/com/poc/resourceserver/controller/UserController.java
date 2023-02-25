package com.poc.resourceserver.controller;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

	
	@GetMapping
	public ResponseEntity<String> getUsers() {
		return ResponseEntity.ok("[{'id': '"+UUID.randomUUID()+"'}]");
	}
	
	@PostMapping
	public ResponseEntity<String> saveUser(@RequestBody String name) {
		return ResponseEntity.ok("[{'id': '"+UUID.randomUUID()+"', 'name': '"+name+"'}]");
	}
}
