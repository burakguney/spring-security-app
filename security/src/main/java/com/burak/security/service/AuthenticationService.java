package com.burak.security.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.burak.security.dto.LoginRequest;
import com.burak.security.dto.LoginResponse;
import com.burak.security.dto.RegisterRequest;
import com.burak.security.dto.RegisterResponse;
import com.burak.security.entity.Role;
import com.burak.security.entity.User;
import com.burak.security.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	public ResponseEntity<String> register(RegisterRequest registerRequest) {
		var user = userRepository.findByEmail(registerRequest.getEmail());
		if (user.isPresent()) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Bu eposta adresi kullanılmış.");
		}

		var newUser = User.builder().firstname(registerRequest.getFirstname()).lastname(registerRequest.getLastname())
				.email(registerRequest.getEmail()).password(passwordEncoder.encode(registerRequest.getPassword()))
				.role(Role.USER).build();

		userRepository.save(newUser);
		return ResponseEntity.status(HttpStatus.OK).body("Kullanıcı başarıyla oluşturuldu.");
	}

	public LoginResponse login(LoginRequest loginRequest) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

		var user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow();

		Map<String, Object> claims = new HashMap<>();
		claims.put("roles", user.getAuthorities());

		var jwtToken = jwtService.generateToken(claims, user);
		return LoginResponse.builder().token(jwtToken).build();
	}

}
