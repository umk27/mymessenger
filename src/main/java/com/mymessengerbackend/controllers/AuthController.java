package com.mymessengerbackend.controllers;

import com.mymessengerbackend.payload.response.JWTTokenSuccessResponse;
import com.mymessengerbackend.payload.response.MessageResponse;
import com.mymessengerbackend.payload.request.LoginRequest;
import com.mymessengerbackend.payload.request.SignupRequest;
import com.mymessengerbackend.security.JWTTokenProvider;
import com.mymessengerbackend.security.SecurityConstants;
import com.mymessengerbackend.services.UserService;
import com.mymessengerbackend.validators.ResponseErrorValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin
@RestController
@RequestMapping("/api/auth")
@PreAuthorize("permitAll()")
public class AuthController {

    private JWTTokenProvider jwtTokenProvider;

    private AuthenticationManager authenticationManager;

    private ResponseErrorValidator responseErrorValidator;

    private UserService userService;

    public AuthController(JWTTokenProvider jwtTokenProvider, AuthenticationManager authenticationManager,
                          ResponseErrorValidator responseErrorValidator, UserService userService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.responseErrorValidator = responseErrorValidator;
        this.userService = userService;
    }

    @PostMapping("/signin")
    public ResponseEntity<Object> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, BindingResult bindingResult) {
        ResponseEntity<Object> errors = responseErrorValidator.mapValidationService(bindingResult);
        if (!ObjectUtils.isEmpty(errors)) return errors;

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
        ));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = SecurityConstants.TOKEN_PREFIX + jwtTokenProvider.generateToken(authentication);

        return ResponseEntity.ok(new JWTTokenSuccessResponse(true, jwt));
    }


    @PostMapping("/signup")
    public ResponseEntity<Object> registerUser(@Valid @RequestBody SignupRequest signupRequest, BindingResult bindingResult) {
        ResponseEntity<Object> errors = responseErrorValidator.mapValidationService(bindingResult);
        if (!ObjectUtils.isEmpty(errors)) return errors;

        userService.createUser(signupRequest);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
