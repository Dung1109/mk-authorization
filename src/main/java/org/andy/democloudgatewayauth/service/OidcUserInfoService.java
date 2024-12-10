package org.andy.democloudgatewayauth.service;


import lombok.RequiredArgsConstructor;
import org.andy.democloudgatewayauth.repo.UserinfoRepository;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class OidcUserInfoService {
    private final UserinfoRepository userinfoRepository;

    // (1)
    public OidcUserInfo loadUser(String username) {
        return new OidcUserInfo(findByUsername(username));
    }

    // (2)
    private Map<String, Object> findByUsername(String username) {
        return userinfoRepository.findByUsername(username)
                .map(userinfo -> OidcUserInfo.builder()
                        .subject(username)
                        .claim("fullname", userinfo.getFullName())
                        .picture(userinfo.getPicture())
                        .email(userinfo.getEmail())
                        .emailVerified(userinfo.getEmailVerified())
                        .gender(userinfo.getGender())
                        .birthdate(toDateString(userinfo.getBirthdate()))
                        .phoneNumber(userinfo.getPhoneNumber())
                        .phoneNumberVerified(userinfo.getPhoneNumberVerified())
                        .claim("address", userinfo.getAddress())
                        .updatedAt(toDateTimeString(userinfo.getUpdatedAt()))
                        .claim("position", userinfo.getPosition())
                        .claim("department", userinfo.getDepartment())
                        .build()
                        .getClaims())
                .orElse(Map.of("sub", username));

    }

    private String toDateString(LocalDate date) {
        return date != null ? date.format(DateTimeFormatter.ISO_DATE) : null;
    }

    private String toDateTimeString(LocalDateTime dateTime) {
        return dateTime != null ? dateTime.format(DateTimeFormatter.ISO_DATE_TIME) : null;
    }
}