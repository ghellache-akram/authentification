package com.trading.app.msauthentication;

import com.trading.app.msauthentication.config.PropertiesUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
@EnableFeignClients
public class MsAuthenticationApplication {

    public static void main(String[] args) {
        PropertiesUtils.initProperties();
        SpringApplication.run(MsAuthenticationApplication.class, args);
    }

}
