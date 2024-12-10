package org.andy.democloudgatewayauth.entity;

import lombok.Data;
import lombok.Value;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * DTO for {@link Userinfo}
 */
@Data
public class UserinfoDto implements Serializable {
    Long id;
    String username;
    String fullName;
    String picture;
    String email;
    Boolean emailVerified;
    String gender;
    LocalDate birthdate;
    String phoneNumber;
    Boolean phoneNumberVerified;
    String address;
    String position;
    String department;
    String note;
    LocalDateTime updatedAt;
    LocalDateTime createdAt;
}