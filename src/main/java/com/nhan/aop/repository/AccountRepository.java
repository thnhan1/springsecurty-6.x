package com.nhan.aop.repository;

import com.nhan.aop.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account, Long> {
    Account findByProviderAndProviderId(String provider, String providerId);
}
