package com.nhan.aop.repository;

import com.nhan.aop.entity.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthTokenRepository extends JpaRepository<AuthToken, Long> {
    AuthToken findByRefreshToken(String refreshToken);
}
