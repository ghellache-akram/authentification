package com.trading.app.msauthentication.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.util.Date;
import java.util.List;


@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
@ToString
@Table(name ="users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String username;

    private String password;

    @Enumerated(EnumType.ORDINAL)
    private ERole role;

    @Column(unique = true)
    private String email;

    private boolean enabled = false;

    private boolean deleted = false;

    private boolean emailConfirmed = false;
    @JsonIgnore
    @OneToOne(mappedBy = "user")
    private Token emailConfirmationToken;
    @JsonIgnore
    @OneToOne(mappedBy = "user")
    private Token passwordResetToken;


    @Temporal(TemporalType.TIMESTAMP)
    private Date lastLogin;
    @JsonIgnore
    @ElementCollection
    private List<String> refreshTokens;
    @JsonIgnore
    @OneToOne(mappedBy = "user")
    private AlpacaCredentials alpacaCredentials;
}
