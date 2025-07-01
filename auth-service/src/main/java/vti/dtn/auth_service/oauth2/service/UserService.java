package vti.dtn.auth_service.oauth2.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import vti.dtn.auth_service.entity.User;
import vti.dtn.auth_service.repository.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User findByUsername(String username) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        return userOptional.orElse(null);
    }
}
