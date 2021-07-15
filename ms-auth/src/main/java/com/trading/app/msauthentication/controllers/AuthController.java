package com.trading.app.msauthentication.controllers;

import com.trading.app.msauthentication.entities.ERole;
import com.trading.app.msauthentication.entities.Token;
import com.trading.app.msauthentication.entities.User;
import com.trading.app.msauthentication.payload.request.*;
import com.trading.app.msauthentication.payload.response.JwtResponse;
import com.trading.app.msauthentication.payload.response.MessageResponse;
import com.trading.app.msauthentication.repositories.TokenRepository;
import com.trading.app.msauthentication.repositories.UserRepository;
import com.trading.app.msauthentication.security.JwtUtils;
import com.trading.app.msauthentication.services.EmailSenderService;
import com.trading.app.msauthentication.services.UserDetailsImp;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Date;
import java.util.UUID;

import static com.trading.app.msauthentication.constant.SecurityConstant.EXPIRATION_TIME;
import static com.trading.app.msauthentication.constant.SecurityConstant.LONG_EXPIRATION_TIME;


//TODO: add send me new email confirmation link
//TODO: set dynamic confirmation link
//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    TokenRepository tokenRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    private EmailSenderService emailSenderService;

    @Value("${serveur.address}")
    private String serveurAddress;

    @Value("${server.port}")
    private int serveurPort;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                               @RequestHeader(value="refresh-token-path", required = false) String path) {
        //Setting refresh-token path depending on the request source
        String refreshTokenPath = (path != null) ? path : "/api/auth/refresh-token";

        //Login the user with the inputs credentials
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImp userDetails = (UserDetailsImp) authentication.getPrincipal();
        //Check if the email is confirmed or not
        if(!userDetails.isEmailConfirmed())
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new MessageResponse("Please confirm your email using the link sent to your mailbox so you can login !"));

        //Check if the account is enabled
        if(!userDetails.isEnabled())
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Account is disabled !"));

        //Check if the account is deleted
        if(userDetails.isDeleted())
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("No user found !"));

        //Generate the jwt to send back to user
        String jwt = jwtUtils.generateJwtToken(authentication);

        //Get the role of the user
        String role = userDetails.getAuthorities().stream().findFirst().get().getAuthority();

        //Build a refresh-token
        String refreshToken = UUID.randomUUID().toString();


        User user = userRepository.findByUsername(userDetails.getUsername());

        //Add the refresh-token to the refresh-token's list
        user.getRefreshTokens().add(refreshToken);

        //Set the last login
        user.setLastLogin(new Date());
        userRepository.save(user);

        // Set the refresh-token cookie
        HttpHeaders headers = new HttpHeaders();
        headers.add("Set-Cookie",
                "refresh-token="+ refreshToken +
                        " ; Path="+refreshTokenPath+" ;  Max-Age=604800  ; HttpOnly");
        //Send back the response to the user
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                role));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser( HttpServletRequest request, @Valid @RequestBody SignupRequest signUpRequest) {

        //Check the existence of the username in the db
        if (userRepository.existsUserByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        //Check the existence of the email in the db
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        //Create the new user account
        User user = new User(null, signUpRequest.getUsername(),passwordEncoder.encode(signUpRequest.getPassword())
                ,null, signUpRequest.getEmail(),false, false, false,
                null,null, null, null,null);

        //Generate the email confirmation token
        String confirmationEmailTokenId = UUID.randomUUID().toString();
        Token confirmationEmailToken = new Token (confirmationEmailTokenId,new Date(System.currentTimeMillis() + LONG_EXPIRATION_TIME),user);

        //Set the user's role
        if (signUpRequest.getRole() == null) {
            user.setRole(ERole.ROLE_USER);
        } else {
                switch (signUpRequest.getRole()) {
                    case ROLE_ADMIN:
                        user.setRole(ERole.ROLE_ADMIN);
                        break;
                    default:
                        user.setRole(ERole.ROLE_USER);

                }
        }

        //Save the  and token in the db
        userRepository.save(user);
        tokenRepository.save(confirmationEmailToken);

        //Sending the email confirmation link to the user's mailbox
        String url = serveurAddress +":" + "7777/auth";
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Complete Your Registration!");
        mailMessage.setFrom("tradingappesisba@gamil.com");
        mailMessage.setText("Hello "+user.getUsername() +",\n \n" +
                "Your request to create a trading account  has been processed.\n \n" +
                "You must now click on the following link:\n \n" +url+
                "/api/auth/confirm-account?token="+ confirmationEmailTokenId +
                "\n \n" +
                "If the link is not displayed correctly, copy the above text to your browser bar.\n \n"+
                "This link will expire in 24 hours.\n \n \n" +
                "Sincerely,"
                );
        emailSenderService.sendEmail(mailMessage);

        //Sending back the success message to the user
        return ResponseEntity.status(HttpStatus.CREATED).body(new MessageResponse("User registered successfully," +
                " An email has been sent to your mailbox to confirm your account"));
    }

    @GetMapping("/confirm-account")
    public ResponseEntity<?> confirmAccount(@RequestParam(value = "token") String token){
        //Check the existence of the confirmation token
        User user = userRepository.findUserByEmailConfirmationTokenId(token);

        //Error message
        if (user == null){
            return ResponseEntity.badRequest().body(new MessageResponse("Error : No user is registered for this token"));
        }

        if (user.getEmailConfirmationToken().getMaxAge().before(new Date())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error : Invalid Token"));
        }

        //Enable the user account
        user.setEmailConfirmed(true);
        user.setEnabled(true);
        userRepository.save(user);
        tokenRepository.delete(tokenRepository.findById(token));

        //Success message
        return ResponseEntity.ok(new MessageResponse("Your email has been confirmed successfully!"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest,
                                          @CookieValue(value= "refresh-token") Cookie refreshToken,
                                          @RequestHeader(value="refresh-token-path", required = false) String path){

        //Setting refresh-token path depending on the request source
        String refreshTokenPath = (path != null) ? path : "/api/auth/refresh-token";

        User user = userRepository.findUserByUsernameAndRefreshTokens(refreshTokenRequest.getUsername(),refreshToken.getValue());
        if (user != null){
            //Generate the new refresh-token
            String newRefreshToken = UUID.randomUUID().toString();

            user.getRefreshTokens().remove(refreshToken.getValue());
            user.getRefreshTokens().add(newRefreshToken);
            userRepository.save(user);

            String jwt = jwtUtils.generateJwtToken(user);

            HttpHeaders headers = new HttpHeaders();
            //Remove the old refresh-token cookie
            headers.add("Set-Cookie",
                    "refresh-token="+ refreshToken.getValue()+
                            " ; Path="+refreshTokenPath+" ; Max-Age=0  ; HttpOnly ; SameSite=Lax");

            //Setting the new refresh-token cookie
            headers.add("Set-Cookie",
                    "refresh-token="+ newRefreshToken+
                            " ; Path="+refreshTokenPath+ " ; Max-Age=604800  ; HttpOnly ; SameSite=Lax");

            return ResponseEntity.status(HttpStatus.OK).headers(headers).body(new JwtResponse(jwt,
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    user.getRole().toString()));
        }

        return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Error: Username or Refresh Token invalid!"));


    }

    @PostMapping("/forget-password")
    public ResponseEntity<?> forgetPassword( HttpServletRequest request,@RequestBody RequestWithUsername  requestWithUsername){

        User user = userRepository.findByUsername(requestWithUsername.getUsername());
        if (user == null){
            return ResponseEntity.badRequest().body(new MessageResponse("Error : No user is registered with this username"));
        }
        //Check if the account is enabled
        if(!user.isEnabled())
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Account is disabled !"));

        //Check if the account is deleted
        if(user.isDeleted())
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("No user found !"));

        String passwordResetTokenId = UUID.randomUUID().toString();
        Token passwordResetToken = new Token (passwordResetTokenId, new Date(System.currentTimeMillis() + EXPIRATION_TIME),user);

        tokenRepository.save(passwordResetToken);

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Resetting your password !");
        mailMessage.setFrom("tradingappesisba@gamil.com");
        mailMessage.setText("Please click the link to reset your password : "+serveurAddress+":"+serveurPort+
                "/api/auth/reset-password?token="+ passwordResetTokenId);
        emailSenderService.sendEmail(mailMessage);

        return ResponseEntity.ok(new MessageResponse("A link has been sent to your mailbox so you can reset your password!"));
    }

    @GetMapping("/reset-password")
    public ResponseEntity<?> resetPasswordConfirmation(@RequestParam(value = "token") String token){

        User user = userRepository.findUserByPasswordResetTokenId(token);

        if (user == null){
            return ResponseEntity.badRequest().body(new MessageResponse("Error : Invalid token!"));
        }

        if (user.getPasswordResetToken().getMaxAge().before(new Date())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error : Invalid Token"));
        }

        return ResponseEntity.ok(new MessageResponse("Your can now reset your password"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam(value = "token") String token, @RequestBody ResetPasswordRequest resetPasswordRequest){

        User user = userRepository.findUserByPasswordResetTokenId(token);

        if (user == null){
            return ResponseEntity.badRequest().body(new MessageResponse("Error : Invalid token!"));
        }

        if (!user.getUsername().equals(resetPasswordRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error : Invalid username!"));
        }

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        user.setPassword(passwordEncoder.encode(resetPasswordRequest.getNewPassword()));

        userRepository.save(user);
        tokenRepository.delete(tokenRepository.findById(token));
        return ResponseEntity.ok(new MessageResponse("New password has been set !"));
    }

}
