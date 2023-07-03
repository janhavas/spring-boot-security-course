package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Antoaneta"),
            new Student(3, "Jamila Kubalovicowska")
    );
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public static List<Student> getAllStudents() {
        return STUDENTS;
    }
    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudents(@RequestBody Student student){

        System.out.println("registerNewStudents");
        System.out.println(student);
    }
    @DeleteMapping(path = "{studentID}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentID") Integer studentId){

        System.out.println("deleteStudent");
        System.out.println(studentId);
    }
    @PutMapping(path = "{studentID}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentID") Integer studentId, @RequestBody Student student){
        System.out.println("updateStudent");
        System.out.printf("%s %s", studentId, student);
    }
}
