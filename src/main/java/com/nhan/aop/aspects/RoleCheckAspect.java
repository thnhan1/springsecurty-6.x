package com.nhan.aop.aspects;

import com.nhan.aop.annotations.RoleRequired;
import java.util.Arrays;
import java.util.Collection;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@Aspect
public class RoleCheckAspect {

  @Around("@annotation(roleRequired)")
  public Object checkRole(ProceedingJoinPoint joinPoint, RoleRequired roleRequired)
      throws Throwable {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (authentication == null || !authentication.isAuthenticated()) {
      throw new AccessDeniedException("Custom Access Denied: User is not authenticated");
    }

    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

    String[] requiredRoles = roleRequired.roles();

    boolean hasRole = Arrays.stream(requiredRoles)
        .anyMatch(role -> authorities.stream()
            .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_" + role)));

    if (!hasRole) {
      throw new AccessDeniedException("Custom Access Denied: Insufficient permissions");
    }

    return joinPoint.proceed();
  }
}