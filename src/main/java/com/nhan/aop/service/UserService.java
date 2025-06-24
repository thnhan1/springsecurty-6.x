package com.nhan.aop.service;

import com.nhan.aop.annotations.RoleRequired;
import com.nhan.aop.dto.UserSignupDto;
import com.nhan.aop.entity.Role;
import com.nhan.aop.entity.User;
import com.nhan.aop.repository.RoleRepository;
import com.nhan.aop.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final RoleRepository roleRepository;

  public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.roleRepository = roleRepository;
  }

  public User registerNewUser(UserSignupDto user) {
    if (userRepository.findByUsername(user.username()) != null) {
      throw new RuntimeException("Username is already exists");
    }

    Role userRole = roleRepository.findByName("ROLE_USER");
    if (userRole == null) {
      userRole = new Role();
      userRole.setName("ROLE_USER");
      roleRepository.save(userRole);
    }

    User newUser = new User();
    newUser.setUsername(user.username());
    newUser.setPassword(passwordEncoder.encode(user.password()));
    newUser.getRoles().add(userRole);
  return  userRepository.save(newUser);
  }

  public User findByUsername(String username) {
    return userRepository.findByUsername(username);
  }

  @RoleRequired(roles = {"USER"})
  public String getUserInfo() {
    return "ADMIN data from service layer";
  }
}
