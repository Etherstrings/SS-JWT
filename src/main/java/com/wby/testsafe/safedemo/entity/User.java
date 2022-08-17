package com.wby.testsafe.safedemo.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 13:57
 */
@Entity
@Data
public class User {

    @Id
    @GeneratedValue
    private Integer id;

    private String username;

    private String password;

    private String role;
}
