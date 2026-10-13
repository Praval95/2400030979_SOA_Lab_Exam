package com.example.jwt.controller;

import org.springframework.web.bind.annotation.*;
import com.example.jwt.service.JwtService;

@RestController
@RequestMapping("/jwt")
public class JwtController {

    private final JwtService jwtService;

    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @GetMapping("/generate/{username}")
    public String generateToken(@PathVariable String username) {
        return jwtService.generateToken(username);
    }

    @GetMapping("/protected")
    public String protectedData() {
        return "Access granted! Valid JWT token.";
    }
}