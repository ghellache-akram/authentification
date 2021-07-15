package com.trading.app.msauthentication.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

@Slf4j
public class PropertiesUtils {

    public static final String SPRING_PROFILES_ACTIVE = "spring.profiles.active";

    public static void initProperties() {
        String activeProfile = System.getProperty(SPRING_PROFILES_ACTIVE);
        if (activeProfile == null) {
            activeProfile = "dev";
        }
        log.info("the active profile is " + activeProfile);
        PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer
                = new PropertySourcesPlaceholderConfigurer();
        Resource[] resources = new ClassPathResource[]
                {new ClassPathResource("application.properties"),
                        new ClassPathResource("application-" + activeProfile + ".properties")};
        propertySourcesPlaceholderConfigurer.setLocations(resources);

    }
}
