package vti.dtn.department_service.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;

import java.time.LocalDate;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class DepartmentDTO {
    private String name;
    private String type;
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate createdDate;
}
