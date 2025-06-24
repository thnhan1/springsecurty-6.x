package com.nhan.aop.service;

import com.nhan.aop.entity.Account;
import com.nhan.aop.entity.AuthToken;
import com.nhan.aop.entity.Role;
import com.nhan.aop.entity.User;
import com.nhan.aop.repository.AccountRepository;
import com.nhan.aop.repository.AuthTokenRepository;
import com.nhan.aop.repository.RoleRepository;
import com.nhan.aop.repository.UserRepository;
import com.nhan.aop.utils.JwtUtil;
import com.nhan.aop.utils.TokenBlacklistService;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final AccountRepository accountRepository;
    private final RoleRepository roleRepository;
    private final AuthTokenRepository authTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService blacklistService;

    public AuthService(UserRepository userRepository,
                       AccountRepository accountRepository,
                       RoleRepository roleRepository,
                       AuthTokenRepository authTokenRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil,
                       TokenBlacklistService blacklistService) {
        this.userRepository = userRepository;
        this.accountRepository = accountRepository;
        this.roleRepository = roleRepository;
        this.authTokenRepository = authTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.blacklistService = blacklistService;
    }

    public UserRepository getUserRepository() {
        return userRepository;
    }

    public User register(String username, String password) {
        if (userRepository.findByUsername(username) != null) {
            throw new RuntimeException("username exists");
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        Role role = roleRepository.findByName("ROLE_USER");
        if (role == null) {
            role = new Role();
            role.setName("ROLE_USER");
            roleRepository.save(role);
        }
        user.getRoles().add(role);
        user = userRepository.save(user);

        Account account = new Account();
        account.setProvider("LOCAL");
        account.setProviderId(username);
        account.setUser(user);
        accountRepository.save(account);

        return user;
    }

    public AuthToken createToken(User user) {
        String refresh = jwtUtil.generateRefreshToken(user.getUsername());
        AuthToken token = new AuthToken();
        token.setRefreshToken(refresh);
        token.setUser(user);
        token.setExpiry(Instant.now().plusMillis(10 * 86400000L));
        return authTokenRepository.save(token);
    }

    public void logout(String accessToken, String refreshToken) {
        blacklistService.blacklist(accessToken, Duration.ofHours(1));
        if (refreshToken != null) {
            blacklistService.blacklist(refreshToken, Duration.ofDays(10));
        }
    }
}
