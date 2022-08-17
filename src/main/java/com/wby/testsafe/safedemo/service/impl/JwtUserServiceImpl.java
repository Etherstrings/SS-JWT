package com.wby.testsafe.safedemo.service.impl;

import com.wby.testsafe.safedemo.entity.JwtUser;
import com.wby.testsafe.safedemo.entity.User;
import com.wby.testsafe.safedemo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.xml.bind.ValidationException;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 17:02
 */
@Service
public class JwtUserServiceImpl implements UserDetailsService {
    @Autowired
    private UserService userService;

    /**
     * 根据前端传入的用户信息 去数据库查询是否存在该用户
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user=userService.findByUsername(username);
        if(user==null){
            throw new UsernameNotFoundException("该用户不存在");
        }
        //JWTUSER是继承于UserDetails的
        JwtUser jwtUser=new JwtUser(user);
        return jwtUser;
    }
}
