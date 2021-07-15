package com.trading.app.msauthentication.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor

public class AlpacaCredRequest {
    private String key;
    private String secret;
}
