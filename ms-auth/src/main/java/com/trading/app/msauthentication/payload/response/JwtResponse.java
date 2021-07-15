package com.trading.app.msauthentication.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class JwtResponse {
    private String token;
    private Long id;
    private String username;
    private String email;
    private String role;

}
