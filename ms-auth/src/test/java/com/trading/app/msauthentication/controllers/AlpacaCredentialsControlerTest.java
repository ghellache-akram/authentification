package com.trading.app.msauthentication.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trading.app.msauthentication.MsAuthenticationApplication;
import com.trading.app.msauthentication.config.DataSourceConfig;
import com.trading.app.msauthentication.entities.ERole;
import com.trading.app.msauthentication.entities.User;
import com.trading.app.msauthentication.payload.request.AlpacaCredRequest;
import com.trading.app.msauthentication.payload.request.RequestWithIdUser;
import com.trading.app.msauthentication.repositories.AlpacaCredentialsRepository;
import com.trading.app.msauthentication.repositories.UserRepository;
import org.junit.jupiter.api.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {MsAuthenticationApplication.class, DataSourceConfig.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AlpacaCredentialsControlerTest {
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private ObjectMapper mapper;

    static final String username1 = "abdenour";

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();

    }

    @BeforeAll
    public static void setupDb(@Autowired UserRepository userRepository){
        userRepository.deleteAll();
        userRepository.save(new User(null, username1, "pwd1",  ERole.ROLE_USER,
                "abdenourbarache@gmail.com", true, false, true,
                null, null,null, null,null ));
    }
    @WithUserDetails(username1)
    @Test
    @Order(1)
    void getAlpacaCredentials_WhenNoCredentialsAreSet_ShouldEndWithBadRequestStatus() throws Exception {
        RequestBuilder request = get ("/api/alpaca/")
                .contentType(MediaType.APPLICATION_JSON_VALUE);
        mockMvc.perform(request).andExpect(status().isBadRequest());
    }

    @WithUserDetails(username1)
    @Test
    @Order(2)
    void addAlpacaCredentials_ShouldEndWithOkStatus() throws Exception{
        RequestBuilder request = post ("/api/alpaca/add")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new AlpacaCredRequest("test", "test")));
        mockMvc.perform(request).andExpect(status().isCreated());
    }

    @WithUserDetails(username1)
    @Test
    @Order(3)
    void getAlpacaCredentials_ShouldEndWithOkStatus() throws Exception {
        RequestBuilder request = get ("/api/alpaca/")
                .contentType(MediaType.APPLICATION_JSON_VALUE);
        mockMvc.perform(request).andExpect(status().isOk());
    }

    @WithUserDetails(username1)
    @Test
    @Order(4)
    void updateAlpacaCredentials() throws Exception {
        RequestBuilder request = put ("/api/alpaca/update")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new AlpacaCredRequest("new key", "new value")));
        mockMvc.perform(request).andExpect(status().isOk());
    }

    @WithUserDetails(username1)
    @Test
    @Order(5)
    void deleteAlpacaCredentials() throws Exception{
        RequestBuilder request = delete ("/api/alpaca/delete")
                .contentType(MediaType.APPLICATION_JSON_VALUE);
        mockMvc.perform(request).andExpect(status().isOk());
    }
    @WithUserDetails(username1)
    @Test
    @Order(6)
    void updateAlpacaCredentials_WhenCredentialsAreDeleted_ShouldEndWithBadRequest() throws Exception {
        RequestBuilder request = put ("/api/alpaca/update")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new AlpacaCredRequest("new key", "new value")));
        mockMvc.perform(request).andExpect(status().isBadRequest());
    }
}