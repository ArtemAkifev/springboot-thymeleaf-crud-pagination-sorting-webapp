package net.java.springboot.service;

import java.util.List;

import net.java.springboot.model.Employee;
import org.springframework.data.domain.Page;

public interface EmployeeService {
    List<Employee> getAllEmployees();

    void saveEmployee(Employee employee);

    Employee getEmployeeById(long id);

    void deleteEmployeeById(long id);

    Page<Employee> findPaginated(int pageNo, int pageSize, String sortField, String sortDirection);
}
