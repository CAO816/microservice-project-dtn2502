package vti.dtn.auth_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import vti.dtn.auth_service.dto.request.LoginRequest;
import vti.dtn.auth_service.dto.request.RegisterRequest;
import vti.dtn.auth_service.dto.response.LoginResponse;
import vti.dtn.auth_service.dto.response.RegisterResponse;
import vti.dtn.auth_service.entity.User;
import vti.dtn.auth_service.entity.enums.Role;
import vti.dtn.auth_service.repository.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public RegisterResponse register(RegisterRequest request){
        String email = request.getEmail();
        String username = request.getUsername();
        String password = request.getPassword();
        String role = request.getRole();
        String firstName = request.getFirstName();
        String lastName = request.getLastName();

        Optional<User> userEntityByEmail = userRepository.findByEmail(email);
        Optional<User> userEntityByUsername = userRepository.findByUsername(username);

        if (userEntityByEmail.isPresent() || userEntityByUsername.isPresent()) {
            return RegisterResponse.builder()
                    .status(400)
                    .message("User already exists!")
                    .build();
        }
        User userEntity = User.builder()
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .email(email)
                .password(passwordEncoder.encode(password)) // Password should be encoded in a real application
                .role(Role.toEnum(role)) // Assuming role is a string, you might want to convert it to an enum
                .build();

        userRepository.save(userEntity);

        return RegisterResponse.builder()
                .status(200)
                .message("User created successfully")
                .build();
    }

    public LoginResponse login(LoginRequest loginRequest){
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        Optional<User> userEntityByUsername = userRepository.findByUsername(username);
        if (userEntityByUsername.isPresent()) {
            User userEntity = userEntityByUsername.get();
            String accessToken = jwtService.generateAccessToken(userEntity);
            String refreshToken = jwtService.generateRefreshToken(userEntity);

            userEntity.setAccessToken(accessToken);
            userEntity.setRefreshToken(refreshToken);
            userRepository.save(userEntity);

            return LoginResponse.builder()
                    .status(HttpStatus.OK.value())
                    .message("Login successful")
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userId(userEntity.getId())
                    .build();
        } else {
            return LoginResponse.builder()
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .message("Invalid credentials")
                    .build();
        }
    }
}
