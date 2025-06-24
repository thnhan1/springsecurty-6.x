package com.nhan.aop.repository;

import com.nhan.aop.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
Role findByName(String name);
}
