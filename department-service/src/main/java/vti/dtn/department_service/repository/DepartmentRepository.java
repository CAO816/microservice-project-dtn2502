package vti.dtn.department_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import vti.dtn.department_service.entity.Department;

public interface DepartmentRepository extends JpaRepository<Department, Integer> {
}
