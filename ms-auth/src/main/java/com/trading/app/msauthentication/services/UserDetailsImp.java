package com.trading.app.msauthentication.services;

import com.trading.app.msauthentication.entities.AlpacaCredentials;
import com.trading.app.msauthentication.entities.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import java.util.Date;
import java.util.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsImp implements UserDetails {

    private Long id;
    private String username;
    private String password;
    private String email;
    private boolean deleted;
    private Date lastLogin;
    private boolean enabled;
    private boolean emailConfirmed;
    private AlpacaCredentials alpacaCredentials;
    private Collection<? extends GrantedAuthority> authorities;

    public static UserDetailsImp build(User user){
        Collection<GrantedAuthority> authorities =  new ArrayList<>();
        authorities.add( new SimpleGrantedAuthority(user.getRole().name()));
        return new UserDetailsImp(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                user.isDeleted(),
                user.getLastLogin(),
                user.isEnabled(),
                user.isEmailConfirmed(),
                user.getAlpacaCredentials(),
                authorities
                );
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImp user = (UserDetailsImp) o;
        return Objects.equals(id, user.id);
    }


}
