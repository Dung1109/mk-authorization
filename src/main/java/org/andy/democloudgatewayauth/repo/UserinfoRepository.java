package org.andy.democloudgatewayauth.repo;

import org.andy.democloudgatewayauth.entity.Userinfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserinfoRepository extends JpaRepository<Userinfo, Long> {

    Optional<Userinfo> findByUsername(String username);
}