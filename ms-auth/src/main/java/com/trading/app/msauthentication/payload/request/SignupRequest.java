package com.trading.app.msauthentication.payload.request;

import com.trading.app.msauthentication.entities.ERole;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor @AllArgsConstructor
public class SignupRequest {
    private String username;
    private String password;
    private String email;
    private ERole role;
}
