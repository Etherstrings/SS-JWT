package com.wby.testsafe.safedemo.controller;

import com.wby.testsafe.safedemo.entity.User;
import com.wby.testsafe.safedemo.service.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 14:04
 */
@RestController
@RequestMapping("/user")
public class UserController {


    @Autowired
    UserServiceImpl userServiceInterface;

    //问题出现在没有注入
    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;

    @PostMapping
    public User save(@RequestBody User parameter) {
        User user = new User();
        user.setUsername(parameter.getUsername());
        String password=parameter.getPassword();
        String enpassword=bCryptPasswordEncoder.encode(password);
        user.setPassword(enpassword);
        if("admin".equals(parameter.getUsername())){
            user.setRole("ADMIN");
        }else{
            user.setRole("USER");
        }
        return userServiceInterface.save(user);
    }

    @GetMapping
    public User findByUsername(@RequestParam String username){
        return userServiceInterface.findByUsername(username);
    }

    @GetMapping("/findAll")
    @PreAuthorize("hasAnyAuthority('ADMIN')")  //这一步很重要 拥有ADMIN权限的用户才能访问该请求
    public List<User> findAll(){
        return userServiceInterface.findAll();
    }

}
