package com.trading.app.msauthentication.controllers;

import com.trading.app.msauthentication.entities.AlpacaCredentials;
import com.trading.app.msauthentication.entities.User;
import com.trading.app.msauthentication.payload.request.AlpacaCredRequest;
import com.trading.app.msauthentication.payload.response.MessageResponse;
import com.trading.app.msauthentication.repositories.AlpacaCredentialsRepository;
import com.trading.app.msauthentication.repositories.UserRepository;
import com.trading.app.msauthentication.services.UserDetailsImp;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;


//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/alpaca")
@Slf4j
public class AlpacaCredentialsControler {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    AlpacaCredentialsRepository alpacaCredentialsRepository;

    @PostMapping("/add")
    public ResponseEntity addAlpacaCredentials(@RequestBody AlpacaCredRequest alpacaCredRequest){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImp userDetails = (UserDetailsImp) authentication.getPrincipal();
        User user  = new User();
        user.setId(userDetails.getId());

        if (alpacaCredentialsRepository.findAlpacaCredentialsByUser(user) != null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new MessageResponse("You already set credentials."));

        AlpacaCredentials alpacaCredentials =
                new AlpacaCredentials(null,alpacaCredRequest.getKey(), alpacaCredRequest.getSecret(), user);

        alpacaCredentialsRepository.save(alpacaCredentials);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new MessageResponse("Alpaca credentials have been set to your account successfully "));
    }
    @GetMapping("/")
    public ResponseEntity getAlpacaCredentials(){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImp userDetails = (UserDetailsImp) authentication.getPrincipal();
        User user  = new User();
        user.setId(userDetails.getId());

        AlpacaCredentials alpacaCredentials = alpacaCredentialsRepository.findAlpacaCredentialsByUser(user);

        if (alpacaCredentials == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Alpaca Credentials are not set for your account"));

        return ResponseEntity.ok().body(alpacaCredentials);
    }

    @PutMapping("/update")
    public ResponseEntity updateAlpacaCredentials(@RequestBody AlpacaCredRequest alpacaCredRequest){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImp userDetails = (UserDetailsImp) authentication.getPrincipal();
        User user  = new User();
        user.setId(userDetails.getId());

        AlpacaCredentials alpacaCredentials = alpacaCredentialsRepository.findAlpacaCredentialsByUser(user);
        if (alpacaCredentials == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Alpaca Credentials are not set for your account"));

        alpacaCredentials.setKey(alpacaCredRequest.getKey());
        alpacaCredentials.setSecret(alpacaCredRequest.getSecret());
        alpacaCredentialsRepository.save(alpacaCredentials);

        return ResponseEntity.ok().body(new MessageResponse("Alpaca credentials have been updated  successfully "));
    }

    @DeleteMapping("/delete")
    public ResponseEntity deleteAlpacaCredentials(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImp userDetails = (UserDetailsImp) authentication.getPrincipal();
        User user  = new User();
        user.setId(userDetails.getId());

        AlpacaCredentials alpacaCredentials = alpacaCredentialsRepository.findAlpacaCredentialsByUser(user);
        if (alpacaCredentials == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Alpaca Credentials are not set for your account"));

        alpacaCredentialsRepository.deleteAlpacaCredentialsById(alpacaCredentials.getId());
        return ResponseEntity.ok().body(new MessageResponse("Alpaca credentials have been deleted successfully "));
    }
}

