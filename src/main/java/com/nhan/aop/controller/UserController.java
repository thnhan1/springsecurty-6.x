package com.nhan.aop.controller;

import com.nhan.aop.annotations.RoleRequired;
import com.nhan.aop.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

  private final UserService userService;

  public UserController(UserService userService) {
    this.userService = userService;
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
    return ResponseEntity.ok(res);
  }

  @GetMapping("/admin")
  public String getAdminData() {
    return userService.getUserInfo();
  }
}
