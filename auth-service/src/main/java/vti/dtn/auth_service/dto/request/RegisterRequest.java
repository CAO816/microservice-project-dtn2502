package vti.dtn.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import vti.dtn.auth_service.entity.enums.Role;

@Getter
@AllArgsConstructor
public class RegisterRequest {
    @NotBlank (message = "Username must be not blank")
    private String username;
    private String firstName;
    private String lastName;
    @Email(message = "Malformed email")
    @NotBlank(message = "Email must be not blank")
    private String email;
    @NotBlank(message = "Password must be not blank")
    private String password;
    @NotBlank(message = "Role must be not blank")
    @Pattern(regexp = "ADMIN|USER|MANAGER")
    private String role;
}
