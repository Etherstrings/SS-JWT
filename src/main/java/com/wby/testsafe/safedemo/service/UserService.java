package com.wby.testsafe.safedemo.service;

import com.wby.testsafe.safedemo.entity.User;

import java.util.List;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 13:56
 */
public interface UserService {

    User save(User user);

    User findByUsername(String username);

    List<User> findAll();
}
