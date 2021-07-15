package com.trading.app.msauthentication.repositories;

import com.trading.app.msauthentication.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String userName);
    boolean existsUserByUsername(String userName);
    boolean existsByEmail(String email);
    User findUserByUsernameAndRefreshTokens(String username, String refreshToken);
    User findUserByEmailConfirmationTokenId(String token);
    User findUserByPasswordResetTokenId(String token);
    User findUserById(Long id);
}
