package com.trading.app.msauthentication.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.trading.app.msauthentication.MsAuthenticationApplication;
import com.trading.app.msauthentication.entities.ERole;
import com.trading.app.msauthentication.entities.User;
import com.trading.app.msauthentication.payload.request.RequestWithIdUser;

import com.trading.app.msauthentication.repositories.UserRepository;
import com.trading.app.msauthentication.config.DataSourceConfig;
import org.junit.jupiter.api.*;


import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;

import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;



@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {MsAuthenticationApplication.class, DataSourceConfig.class} ,webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ManagementControllerTest {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext context;


    @Autowired
    private ObjectMapper mapper;

    static final String username1 = "abdenour";
    static final String username2 = "abdenour97";


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
        userRepository.save(new User(1L, username1, "pwd1",  ERole.ROLE_ADMIN,
                "abdenourbarache@gmail.fr", true, false, true,
                null, null,null, null,null ));
        userRepository.save(new User(2L, username2, "pwd2",  ERole.ROLE_USER,
                "a.barache@gmail.fr", true, false, true,
                null, null,null, null, null ));

    }

    @WithMockUser(username="admin")
    @Test
    @Order(1)
    void setAsAdmin_FromSimpleUser_ShouldEndWithForbiddenStatus() throws Exception {

        RequestBuilder request = put ("/api/management/setasadmin")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new RequestWithIdUser(2L)));
        mockMvc.perform(request).andExpect(status().isForbidden());

    }

    @WithMockUser(username="admin",roles={"ADMIN"})
    @Test
    @Order(2)
    void setAsAdmin() throws Exception {

        RequestBuilder request = put ("/api/management/setasadmin")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new RequestWithIdUser(2L)));
        mockMvc.perform(request).andExpect(status().isOk());

    }
    @WithMockUser(username="admin",roles={"ADMIN"})
    @Test
    @Order(3)
    void banUser() throws Exception{
        RequestBuilder request = put ("/api/management/banuser")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new RequestWithIdUser(2L)));
        mockMvc.perform(request).andExpect(status().isOk());
    }

    @WithMockUser(username="admin",roles={"ADMIN"})
    @Test
    @Order(4)
    void unBanUser()throws Exception {
        RequestBuilder request = put ("/api/management/unbanuser")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new RequestWithIdUser(2L)));
        mockMvc.perform(request).andExpect(status().isOk());
    }

    @WithUserDetails(username2)
    @Test
    @Order(5)
    void deleteMyAccount() throws Exception{
        RequestBuilder request = put ("/api/management/deletemyaccount")
                .contentType(MediaType.APPLICATION_JSON_VALUE);
        mockMvc.perform(request).andExpect(status().isOk());
    }
    @WithMockUser(username="admin",roles={"ADMIN"})
    @Test
    @Order(6)
    void testDeleteAccount() throws Exception{
        RequestBuilder request = put ("/api/management/deleteaccount")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(mapper.writeValueAsString(new RequestWithIdUser(1L)));
        mockMvc.perform(request).andExpect(status().isOk());
    }



}