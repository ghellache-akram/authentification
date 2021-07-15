package com.trading.app.msauthentication.controllers;


import com.trading.app.msauthentication.entities.ERole;
import com.trading.app.msauthentication.entities.User;
import com.trading.app.msauthentication.payload.request.RequestWithIdUser;
import com.trading.app.msauthentication.payload.request.RequestWithUsername;
import com.trading.app.msauthentication.payload.response.MessageResponse;
import com.trading.app.msauthentication.repositories.UserRepository;
import com.trading.app.msauthentication.services.UserDetailsImp;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/management")
@Slf4j
public class ManagementController {

    //TODO: Change my password endpoint
    //TODO : Get all users accounts
    @Autowired
    UserRepository userRepository;

    @GetMapping("/getallusers")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity getAllUsers() {

        List<User> users = userRepository.findAll();

        return ResponseEntity.ok(users);
    }
    @PutMapping("/setasadmin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity setAsAdmin(@RequestBody RequestWithIdUser requestWithIdUser) {

        User user = userRepository.findUserById(requestWithIdUser.getId());
        if(user == null)
            return ResponseEntity.badRequest().body(new MessageResponse("No user is registered with this username !"));
        if (user.getRole() == ERole.ROLE_ADMIN )
            return ResponseEntity.badRequest().body(new MessageResponse("User is already an admin!"));

        user.setRole(ERole.ROLE_ADMIN);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User role set to admin successfully"));
    }

    @PutMapping("/banuser")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity banUser(@RequestBody RequestWithIdUser requestWithIdUser) {

        User user = userRepository.findUserById(requestWithIdUser.getId());
        if(user == null)
            return ResponseEntity.badRequest().body(new MessageResponse("No user is registered with this username !"));
        if (!user.isEnabled())
            return ResponseEntity.badRequest().body(new MessageResponse("User  is already banned !"));

        user.setEnabled(false);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User is banned successfully"));
    }

    @PutMapping("/unbanuser")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity unBanUser(@RequestBody RequestWithIdUser requestWithIdUser) {

        User user = userRepository.findUserById(requestWithIdUser.getId());
        if(user == null)
            return ResponseEntity.badRequest().body(new MessageResponse("No user is registered with this username !"));
        if (user.isEnabled())
            return ResponseEntity.badRequest().body(new MessageResponse("User is already unbanned !"));

        user.setEnabled(true);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User is unbanned successfully"));
    }

    @PutMapping("/deletemyaccount")
    public ResponseEntity deleteMyAccount() {
        UserDetailsImp userDetails = (UserDetailsImp) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = userRepository.findUserById(userDetails.getId());

        if (user.isDeleted())
            return ResponseEntity.badRequest().body(new MessageResponse("User is already deleted !"));

        user.setDeleted(true);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User is deleted successfully"));
    }
    @PutMapping("/deleteaccount")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity deleteAccount(@RequestBody RequestWithIdUser requestWithIdUser) {
        User user = userRepository.findUserById(requestWithIdUser.getId());
        if(user == null)
            return ResponseEntity.badRequest().body(new MessageResponse("No user is registered with this username !"));
        if (user.isDeleted())
            return ResponseEntity.badRequest().body(new MessageResponse("User is already deleted !"));
        user.setDeleted(true);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User is deleted successfully"));
    }

}
