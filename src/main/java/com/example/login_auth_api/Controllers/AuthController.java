package com.example.login_auth_api.Controllers;

import com.example.login_auth_api.domain.user.User;
import com.example.login_auth_api.dto.LoginRequestDto;
import com.example.login_auth_api.dto.LoginResponseDto;
import com.example.login_auth_api.dto.RegisterRequestDto;
import com.example.login_auth_api.repositories.UserRepository;
import com.example.login_auth_api.security.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDto body) {
        User user = this.userRepository.findByEmail(body.email()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (passwordEncoder.matches(body.password(), user.getPassword())){
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new LoginResponseDto(user.getName(), user.getPassword()));
        }

        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDto body){
        Optional<User> user = this.userRepository.findByEmail(body.email());

        if(user.isEmpty()) {
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.userRepository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new LoginResponseDto(newUser.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }
}
