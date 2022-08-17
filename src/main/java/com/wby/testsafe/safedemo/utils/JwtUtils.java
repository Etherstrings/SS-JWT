package com.wby.testsafe.safedemo.utils;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 14:06
 */

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * jwt 工具类 主要是生成token 检查token等相关方法
 */
public class JwtUtils {
    //Token 前缀信息
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    // TOKEN 过期时间
    public static final long EXPIRATION = 1000 * 60 * 30; // 三十分

    // 设置生成JWT使用的秘钥
    private static final String JWT_SECRET_KEY = "I konw what is meaning now";

    //生成Token方法
    //根据传入的用户名称+角色生成
    public static String createToken(String username,String role){
        Map<String,Object> map=new HashMap<>();
        map.put("role",role);
        String Token=Jwts.builder()
                //设置分类是什么？----username的JWT
                .setSubject(username)
                .setClaims(map)
                .claim("username",username)

                //设置有效开始时间
                .setIssuedAt(new Date())
                //设置结束时间
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION))
                //设置加密方式
                //加密算法+密匙（就是解密JWT的关键）
                .signWith(SignatureAlgorithm.HS256,JWT_SECRET_KEY).compact();
        return Token;
    }

    //通过JWT-token获取用户名
    public static String getuserNameByJWT(String token){
        String userName= Jwts.parser().setSigningKey(JWT_SECRET_KEY).parseClaimsJws(token).getBody()
                .get("username").toString();
        return userName;
    }

    //通过JWT-token获取用户对应的角色
    public static String getRoleByJWT(String token){
        String role=Jwts.parser().setSigningKey(JWT_SECRET_KEY).parseClaimsJws(token).getBody()
                .get("role").toString();
        return role;
    }

    /**
     * 获解析token中的信息
     * Body就是一个HashMap
     * @param token
     * @return
     */
    public static Claims checkJWT(String token) {
        try {
            final Claims claims = Jwts.parser().setSigningKey(JWT_SECRET_KEY).parseClaimsJws(token).getBody();
            return claims;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 检查token是否过期
     *
     * @param token
     * @return
     */
    public static boolean isExpiration(String token) {
        Claims claims = Jwts.parser().setSigningKey(JWT_SECRET_KEY).parseClaimsJws(token).getBody();
        return claims.getExpiration().before(new Date());
    }


}
