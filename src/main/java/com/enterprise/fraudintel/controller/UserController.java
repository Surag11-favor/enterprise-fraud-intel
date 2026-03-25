package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.User;
import com.enterprise.fraudintel.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @PostMapping("/invite")
    public User inviteUser(@RequestBody User user) {
        // Use provided password or default to 'password123' if empty
        String rawPassword = (user.getPassword() != null && !user.getPassword().isEmpty()) 
            ? user.getPassword() : "password123";
        user.setPassword(passwordEncoder.encode(rawPassword));
        if (user.getRole() == null) user.setRole("USER");
        return userRepository.save(user);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable @org.springframework.lang.NonNull Long id) {
        userRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }
}
