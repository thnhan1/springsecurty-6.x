package com.nhan.aop.service;

import com.nhan.aop.annotations.RoleRequired;
import com.nhan.aop.entity.User;
import com.nhan.aop.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {
  private final UserRepository userRepository;

  public UserService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  public User findByUsername(String username) {
    return userRepository.findByUsername(username);
  }

  @RoleRequired(roles = {"USER"})
  public String getUserInfo() {
    return "ADMIN data from service layer";
  }
}
