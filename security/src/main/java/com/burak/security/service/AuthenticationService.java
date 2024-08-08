package com.burak.security.service;

import java.util.HashMap;
import java.util.Map;

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

	public RegisterResponse register(RegisterRequest registerRequest) {
		var user = userRepository.findByEmail(registerRequest.getEmail());
		if(user.isPresent()) {
			return RegisterResponse.builder().result("Bu eposta adresi kullanılmış.").build();
		}
		
		var newUser = User.builder().firstname(registerRequest.getFirstname()).lastname(registerRequest.getLastname())
				.email(registerRequest.getEmail()).password(passwordEncoder.encode(registerRequest.getPassword()))
				.role(Role.USER).build();
		
		userRepository.save(newUser);
		return RegisterResponse.builder().result("Kullanıcı başarıyla oluşturuldu.").build();
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
