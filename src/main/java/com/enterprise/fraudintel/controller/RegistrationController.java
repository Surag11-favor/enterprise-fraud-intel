package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.User;
import com.enterprise.fraudintel.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
public class RegistrationController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public RegistrationController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/register")
    public String showRegistrationForm() {
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username, 
                               @RequestParam String password, 
                               @RequestParam String email) {
        
        // Basic Validation
        if (username.length() < 4) {
             return "redirect:/register?error=" + encode("IDENTIFIER_TOO_SHORT");
        }
        if (password.length() < 6) {
             return "redirect:/register?error=" + encode("KEY_STRENGTH_INSUFFICIENT");
        }
        if (!email.contains("@")) {
             return "redirect:/register?error=" + encode("INVALID_CONTACT_QUERY");
        }

        if (userRepository.findByUsername(username).isPresent()) {
            return "redirect:/register?error=" + encode("USER_EXISTS_IN_REGISTRY");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setEmail(email);
        user.setRole("USER");

        userRepository.save(user);
        return "redirect:/login?registered";
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
