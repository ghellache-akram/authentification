package com.trading.app.msauthentication.repositories;

import com.trading.app.msauthentication.entities.AlpacaCredentials;
import com.trading.app.msauthentication.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface AlpacaCredentialsRepository extends JpaRepository<AlpacaCredentials, String> {

    AlpacaCredentials findAlpacaCredentialsByUser(User user);
    @Transactional
    void deleteAlpacaCredentialsById(Long id);

}
