package com.trading.app.msauthentication.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trading.app.msauthentication.entities.ERole;
import com.trading.app.msauthentication.entities.Token;
import com.trading.app.msauthentication.entities.User;
import com.trading.app.msauthentication.payload.request.LoginRequest;
import com.trading.app.msauthentication.payload.request.RefreshTokenRequest;
import com.trading.app.msauthentication.payload.request.ResetPasswordRequest;
import com.trading.app.msauthentication.payload.request.SignupRequest;
import com.trading.app.msauthentication.repositories.TokenRepository;
import com.trading.app.msauthentication.repositories.UserRepository;
import com.trading.app.msauthentication.security.AuthEntryPointJwt;
import com.trading.app.msauthentication.security.JwtUtils;
import com.trading.app.msauthentication.services.EmailSenderService;
import com.trading.app.msauthentication.services.UserDetailsImp;
import com.trading.app.msauthentication.services.UserDetailsServiceImp;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;

import javax.servlet.http.Cookie;
import java.util.*;

import static com.trading.app.msauthentication.constant.SecurityConstant.EXPIRATION_TIME;
import static com.trading.app.msauthentication.constant.SecurityConstant.LONG_EXPIRATION_TIME;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @MockBean
    UserRepository userRepository;
    @MockBean
    TokenRepository tokenRepository;
    @MockBean
    EmailSenderService emailSenderService;
    @MockBean
    PasswordEncoder passwordEncoder;
    @MockBean
    UserDetailsServiceImp userDetailsServiceImp;
    @MockBean
    AuthEntryPointJwt unauthorizedHandler;
    @MockBean
    JwtUtils jwtUtils;
    @MockBean
    AuthenticationManager authenticationManager;

    static final String username = "abdenour";
    static final String password = "abdenourba";
    static final String email  = "abdenourbarache@gmail.com";


    @Test
    void authenticateUser_ShouldEndUpWithTheRightInfoAndSuccessStatus() throws Exception{

        Collection<GrantedAuthority> authorities =  new ArrayList<>();
        authorities.add( new SimpleGrantedAuthority(ERole.ROLE_USER.toString()));

        UserDetailsImp userDetailsImp = new UserDetailsImp(null,username,password,email,false, null,
                true, true,null, authorities);

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(authentication.getPrincipal())
                .thenReturn(userDetailsImp);
        when(jwtUtils.generateJwtToken(any(Authentication.class))).thenReturn(anyString());
        User user = new User();
        user.setRefreshTokens(new ArrayList<>());
        when(userRepository.findByUsername(username)).thenReturn(user);

        LoginRequest loginRequest = new LoginRequest(username,password);

        RequestBuilder request = post ("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsBytes(loginRequest));

        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value(ERole.ROLE_USER.toString()));
    }

    @Test
    void authenticateUser_BlockedUser_ShouldEndWithUnauthorizedStatus() throws Exception{

        Collection<GrantedAuthority> authorities =  new ArrayList<>();
        authorities.add( new SimpleGrantedAuthority(ERole.ROLE_USER.toString()));

        UserDetailsImp userDetailsImp = new UserDetailsImp(null,username,password,email,false, null,
                false, true, null,   authorities);

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal())
                .thenReturn(userDetailsImp);
        when(jwtUtils.generateJwtToken(any(Authentication.class))).thenReturn(anyString());
        User user = new User();
        user.setRefreshTokens(new ArrayList<>());
        when(userRepository.findByUsername(username)).thenReturn(user);

        LoginRequest loginRequest = new LoginRequest(username,password);

        RequestBuilder request = post ("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsBytes(loginRequest));

        mockMvc.perform(request)
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authenticateUser_EmailNotConfirmed_ShouldEndWithUnauthorizedStatus() throws Exception{

        Collection<GrantedAuthority> authorities =  new ArrayList<>();
        authorities.add( new SimpleGrantedAuthority(ERole.ROLE_USER.toString()));

        UserDetailsImp userDetailsImp = new UserDetailsImp(null,username,password,email,false, null,
                true, false,null, authorities);

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal())
                .thenReturn(userDetailsImp);
        when(jwtUtils.generateJwtToken(any(Authentication.class))).thenReturn(anyString());
        User user = new User();
        user.setRefreshTokens(new ArrayList<>());
        when(userRepository.findByUsername(username)).thenReturn(user);

        LoginRequest loginRequest = new LoginRequest(username,password);

        RequestBuilder request = post ("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsBytes(loginRequest));

        mockMvc.perform(request)
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registerUser_ShouldEndWithStatusCreated() throws Exception{
        when(userRepository.existsUserByUsername(username)).thenReturn(false);
        when(userRepository.existsByEmail(email)).thenReturn(false);
        when(userRepository.save(any(User.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        when(tokenRepository.save(any(Token.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(emailSenderService).sendEmail(any(SimpleMailMessage.class));

        SignupRequest signupRequest = new SignupRequest(username, password, email, ERole.ROLE_ADMIN);
        
        RequestBuilder request = post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(signupRequest));

        mockMvc.perform(request).andExpect(status().isCreated());
    }

    @Test
    void registerUser_ShouldEndWithEmailAlreadyUsed() throws Exception{
        when(userRepository.existsUserByUsername(username)).thenReturn(false);
        when(userRepository.existsByEmail(email)).thenReturn(true);
        when(userRepository.save(any(User.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        when(tokenRepository.save(any(Token.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(emailSenderService).sendEmail(any(SimpleMailMessage.class));

        SignupRequest signupRequest = new SignupRequest(username, password, email, ERole.ROLE_ADMIN);

        RequestBuilder request = post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(signupRequest));

        mockMvc.perform(request).andExpect(status().isBadRequest());
    }

    @Test
    void registerUser_ShouldEndWithUsernameAlreadyUsed() throws Exception{
        when(userRepository.existsUserByUsername(username)).thenReturn(true);
        when(userRepository.existsByEmail(email)).thenReturn(false);
        when(userRepository.save(any(User.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        when(tokenRepository.save(any(Token.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(emailSenderService).sendEmail(any(SimpleMailMessage.class));

        SignupRequest signupRequest = new SignupRequest(username, password, email, ERole.ROLE_ADMIN);

        RequestBuilder request = post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(signupRequest));

        mockMvc.perform(request).andExpect(status().isBadRequest());
    }

    @Test
    void confirmAccount_ShouldEndWithSuccessStatus() throws Exception{
        User user = new User();
        String confirmationEmailTokenId = UUID.randomUUID().toString();
        Token confirmationEmailToken = new Token (confirmationEmailTokenId,new Date(System.currentTimeMillis() + LONG_EXPIRATION_TIME),user);
        user.setEmailConfirmationToken(confirmationEmailToken);

        when(userRepository.findUserByEmailConfirmationTokenId(anyString())).thenReturn(user);
        when(userRepository.save(any(User.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(tokenRepository).delete(any(Token.class));
        when(tokenRepository.findById(anyString())).thenReturn(confirmationEmailToken);

        RequestBuilder request = get("/api/auth/confirm-account")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .param("token", confirmationEmailTokenId);

        mockMvc.perform(request).andExpect(status().isOk());

    }

    @Test
    void confirmAccount_TokenExpired_ShouldEndWithBadRequestStatus() throws Exception{
        User user = new User();
        String confirmationEmailTokenId = UUID.randomUUID().toString();
        Token confirmationEmailToken = new Token (confirmationEmailTokenId,new Date(System.currentTimeMillis() - LONG_EXPIRATION_TIME),user);
        user.setEmailConfirmationToken(confirmationEmailToken);

        when(userRepository.findUserByEmailConfirmationTokenId(anyString())).thenReturn(user);
        when(userRepository.save(any(User.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(tokenRepository).delete(any(Token.class));
        when(tokenRepository.findById(anyString())).thenReturn(confirmationEmailToken);

        RequestBuilder request = get("/api/auth/confirm-account")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .param("token", confirmationEmailTokenId);

        mockMvc.perform(request).andExpect(status().isBadRequest());

    }

    @Test
    void refreshToken_ShouldEndWithSuccessStatusAndVerifiedInfo() throws Exception{

        String oldRefreshToken = UUID.randomUUID().toString();
        List refreshTokens = new ArrayList();
        refreshTokens.add(oldRefreshToken);
        User user = new User(null, username, null , ERole.ROLE_USER, email, true, false,
                true, null, null,null, refreshTokens,null);

        Cookie cookie = new Cookie("refresh-token", oldRefreshToken +
                " ; Path=/api/auth/refresh-token ; Max-Age=604800  ; HttpOnly ; SameSite=Lax");

        when(userRepository.findUserByUsernameAndRefreshTokens(anyString(),anyString())).thenReturn(user);
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        when(jwtUtils.generateJwtToken(any(Authentication.class))).thenReturn(null);

        RequestBuilder request = post("/api/auth/refresh-token")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .cookie(cookie)
                .content(objectMapper.writeValueAsString(new RefreshTokenRequest(username)));

        mockMvc.perform(request).andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value(ERole.ROLE_USER.toString()));
    }
    @Test
    void forgetPassword_ShouldEndWithSuccessStatus() throws Exception{
        User user = new User();
        user.setEnabled(true);
        user.setDeleted(false);

        when(userRepository.findByUsername(username)).thenReturn(user);
        when(tokenRepository.save(any(Token.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(emailSenderService).sendEmail(any(SimpleMailMessage.class));

        RequestBuilder request = post("/api/auth/forget-password")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(new RefreshTokenRequest(username)));

        mockMvc.perform(request).andExpect(status().isOk());
    }
    @Test
    void restPasswordConfirmation_ShouldEndWithSuccessStatus() throws Exception{
        User user = new User();
        String passwordResetTokenId = UUID.randomUUID().toString();
        Token passwordResetToken = new Token (passwordResetTokenId, new Date(System.currentTimeMillis() + EXPIRATION_TIME),user);
        user.setPasswordResetToken(passwordResetToken);

        when(userRepository.findUserByPasswordResetTokenId(passwordResetTokenId)).thenReturn(user);
        when(tokenRepository.save(any(Token.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(emailSenderService).sendEmail(any(SimpleMailMessage.class));

        RequestBuilder request = get("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .param("token", passwordResetTokenId);

        mockMvc.perform(request).andExpect(status().isOk());
    }

    @Test
    void restPassword_ShouldEndWithSuccessStatus() throws Exception{
        User user = new User();
        user.setUsername(username);
        String passwordResetTokenId = UUID.randomUUID().toString();
        Token passwordResetToken = new Token (passwordResetTokenId, new Date(System.currentTimeMillis() + EXPIRATION_TIME),user);
        user.setPasswordResetToken(passwordResetToken);

        when(userRepository.findUserByPasswordResetTokenId(passwordResetTokenId)).thenReturn(user);
        when(tokenRepository.save(any(Token.class)))
                .thenAnswer(i -> i.getArguments()[0]);
        doNothing().when(emailSenderService).sendEmail(any(SimpleMailMessage.class));
        ResetPasswordRequest re = new ResetPasswordRequest("test","test");
        RequestBuilder request = post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .param("token", passwordResetTokenId)
                .content(objectMapper.writeValueAsString(new ResetPasswordRequest(username,"newpwd")));

        mockMvc.perform(request).andExpect(status().isOk());
    }



}