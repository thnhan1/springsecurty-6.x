package com.nhan.aop.controller;

import com.nhan.aop.annotations.RoleRequired;
import com.nhan.aop.dto.JwtAuthenticationResponse;
import com.nhan.aop.dto.LoginRequest;
import com.nhan.aop.dto.UserSignupDto;
import com.nhan.aop.filter.JwtTokenProvider;
import com.nhan.aop.entity.User;
import com.nhan.aop.security.CustomUserDetailsService;
import com.nhan.aop.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

  private static final Logger logger = LoggerFactory.getLogger(UserController.class);
  private final UserService userService;
  private final PasswordEncoder passwordEncoder;
  private final CustomUserDetailsService customUserDetailsService;
  private final AuthenticationManager authenticationManager;
  private final JwtTokenProvider jwtTokenProvider;

  public UserController(UserService userService, PasswordEncoder passwordEncoder,
      CustomUserDetailsService customUserDetailsService,
      AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
    this.userService = userService;
    this.passwordEncoder = passwordEncoder;
    this.customUserDetailsService = customUserDetailsService;
    this.authenticationManager = authenticationManager;
    this.jwtTokenProvider = jwtTokenProvider;
  }

  @PostMapping("/users/signup")
  public ResponseEntity<String> registerUser(@RequestBody UserSignupDto userSignupDto) {
    try {
      User registeredUser = userService.registerNewUser(userSignupDto);
      return ResponseEntity.status(HttpStatus.OK).body("User register ok");
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(e.getMessage());
    }
  }

  @PostMapping("/login")
  public ResponseEntity<JwtAuthenticationResponse> loginUser(@RequestBody LoginRequest loginUser,
      HttpServletResponse response) {
    Authentication authentication
        = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginUser.username(),
            loginUser.password()
        ));

    logger.info("Authenticated user ok: {}", authentication.getName());

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtTokenProvider.generateToken(authentication);

    response.setHeader("Authorization", "Bearer " + jwt);

    return ResponseEntity.status(HttpStatus.OK).body(new JwtAuthenticationResponse(jwt));
  }


  @GetMapping("/user")
  @RoleRequired(roles = {"USER"})
  public ResponseEntity<Map<String, String>> getUserData(HttpServletRequest request) {
    Map<String, String> res = new HashMap<>();

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    String jwtFromHeader = request.getHeader("Authorization");

    res.put("username", authentication.getName());
    res.put("authorities", authentication.getAuthorities().toString());
    res.put("jwt", jwtFromHeader);
    return ResponseEntity.status(HttpStatus.OK).body(res);
  }

  @GetMapping("/admin")
  public String getAdminData() {
    return userService.getUserInfo();
  }
}
