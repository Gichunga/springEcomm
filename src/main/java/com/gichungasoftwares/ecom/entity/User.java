package com.gichungasoftwares.ecom.entity;

import com.gichungasoftwares.ecom.enums.UserRole;
import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;
    private String password;
    private String name;
    private UserRole role;

    //store the user image
    @Lob
    @Column(columnDefinition = "longblob")
    private byte[] img;
}
