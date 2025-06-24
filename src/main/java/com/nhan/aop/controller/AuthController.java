package com.nhan.aop.controller;

import com.nhan.aop.dto.LoginRequest;
import com.nhan.aop.dto.LoginResponse;
import com.nhan.aop.dto.RefreshRequest;
import com.nhan.aop.dto.RegisterRequest;
import com.nhan.aop.entity.AuthToken;
import com.nhan.aop.entity.User;
import com.nhan.aop.repository.AuthTokenRepository;
import com.nhan.aop.service.AuthService;
import com.nhan.aop.utils.JwtUtil;
import com.nhan.aop.utils.TokenBlacklistService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final AuthTokenRepository authTokenRepository;
    private final TokenBlacklistService blacklistService;

    public AuthController(AuthService authService,
                          AuthenticationManager authenticationManager,
                          JwtUtil jwtUtil,
                          AuthTokenRepository authTokenRepository,
                          TokenBlacklistService blacklistService) {
        this.authService = authService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.authTokenRepository = authTokenRepository;
        this.blacklistService = blacklistService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        User user = authService.register(request.email(), request.name(), request.password());
        AuthToken refresh = authService.createToken(user);
        String access = jwtUtil.generateAccessToken(user.getUsername());
        return ResponseEntity.ok(new LoginResponse(access, refresh.getRefreshToken()));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String username = authentication.getName();
        User user = authService.getUserRepository().findByUsername(username);
        AuthToken refresh = authService.createToken(user);
        String access = jwtUtil.generateAccessToken(username);
        return ResponseEntity.ok(new LoginResponse(access, refresh.getRefreshToken()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@RequestBody RefreshRequest request) {
        AuthToken token = authTokenRepository.findByRefreshToken(request.refreshToken());
        if (token == null || blacklistService.isBlacklisted(request.refreshToken())) {
            return ResponseEntity.badRequest().build();
        }
        String username = token.getUser().getUsername();
        String access = jwtUtil.generateAccessToken(username);
        return ResponseEntity.ok(new LoginResponse(access, request.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader,
                                       @RequestBody(required = false) RefreshRequest refresh) {
        String token = authHeader.replace("Bearer ", "");
        String refreshToken = refresh != null ? refresh.refreshToken() : null;
        authService.logout(token, refreshToken);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    public ResponseEntity<String> me(Authentication authentication) {
        return ResponseEntity.ok(authentication.getName());
    }
}
