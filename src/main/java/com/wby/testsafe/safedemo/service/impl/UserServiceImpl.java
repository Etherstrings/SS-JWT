package com.wby.testsafe.safedemo.service.impl;

import com.wby.testsafe.safedemo.entity.User;
import com.wby.testsafe.safedemo.mapper.UserRepostitory;
import com.wby.testsafe.safedemo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 14:02
 */
@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepostitory userRepostitory;

    @Override
    public User save(User user) {
        return userRepostitory.save(user);
    }

    @Override
    public User findByUsername(String username) {
        return userRepostitory.findByUsername(username);
    }

    @Override
    public List<User> findAll() {
        return userRepostitory.findAll();
    }
}
