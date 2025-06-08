package vti.dtn.department_service.service;

import vti.dtn.department_service.dto.DepartmentDTO;
import vti.dtn.department_service.entity.Department;

import java.util.List;

public interface DepartmentService {
    List<DepartmentDTO> getListDepartments();
}
