package com.wby.testsafe.safedemo.mapper;

import com.wby.testsafe.safedemo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 13:59
 */
@Repository
public interface UserRepostitory extends JpaRepository<User,Long> {

    User save(User user);

    User findByUsername(String userName);

    List<User> findAll();
}
