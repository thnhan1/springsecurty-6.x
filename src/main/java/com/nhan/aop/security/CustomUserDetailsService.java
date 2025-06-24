package com.nhan.aop.security;

import com.nhan.aop.entity.Role;
import com.nhan.aop.entity.User;
import com.nhan.aop.repository.UserRepository;
import java.util.Collection;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.task.TaskExecutionProperties;
import org.springframework.boot.autoconfigure.task.TaskExecutionProperties.Simple;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
  private final UserRepository userRepository;
  public CustomUserDetailsService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username);
    if (user == null) {
      throw new UsernameNotFoundException("user not found with username: " + username);
    }

    return new CustomUserDetails(
        user.getId(),
        user.getUsername(),
        user.getPassword(),
        user.isEnabled(),
        mapRolesToAuthorities(user.getRoles())
    );
  }

  private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
    return roles.stream()
        .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toList());
  }
}
