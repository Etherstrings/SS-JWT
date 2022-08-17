package com.wby.testsafe.safedemo.filter;


import com.wby.testsafe.safedemo.entity.JwtUser;
import com.wby.testsafe.safedemo.entity.User;
import com.wby.testsafe.safedemo.utils.JwtUtils;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-11 17:17
 */

/**
 * 验证用户名密码正确后，生成一个token，并将token返回给客户端
 * 该类继承自UsernamePasswordAuthenticationFilter，重写了其中的2个方法
 *
 * 1.attemptAuthentication：接收并解析用户凭证。
 * 2.successfulAuthentication：用户成功登录后，这个方法会被调用，我们在这个方法里生成token并返回。
 */

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    //基于JWT的权限过滤器

    //认证管理器----里面存了认证的几种方式
    //最开始的父类验证方式管理器
    private AuthenticationManager authenticationManager;



    //设置权限过滤器的构造器---初始化就按照需求的模式进行设置
    public JWTAuthenticationFilter(){

    }
    /**
     * security拦截默认是以POST形式走/login请求，我们这边设置为走/token请求
     * @param authenticationManager
     */
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager=authenticationManager;
        super.setFilterProcessesUrl("/token");
    }

    /**
     * 接收并解析用户凭证
     * @param request
     * @param response
     * @return Authentication----用户权限对象---认证前后
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //重写认证过滤器当中的尝试认证方法

        //从输入流中获取登录信息
        try{
            User loginUser = new ObjectMapper().readValue(request.getInputStream(), User.class);
            //执行认证方法
            //返回一个认证后的 包含更多信息的认证对象
            //通过用户账号密码Token鉴定权类
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginUser.getUsername(),loginUser.getPassword())
            );
        }catch (IOException e){
            e.printStackTrace();
            return null;
        }
    }


    //验证成功后的自动执行
    //将返回的response中带上验证成功的JWT
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //Authentication类获得主体---也就是继承了Security的实体类
        JwtUser jwtUser=(JwtUser)authResult.getPrincipal();

        //从认证成功后的认证类中提取注册的用户主体
        //再从用户主体中取出用户的角色
        List<String> roles=new ArrayList<>();
        Collection<? extends GrantedAuthority> authorities = jwtUser.getAuthorities();
        for(GrantedAuthority authority:authorities){
            roles.add(authority.getAuthority());
        }
        //后端构建Token主体
        String token = JwtUtils.createToken(jwtUser.getUsername(), roles.get(0));
        //后端构建传给前端的Token本体
        //JWT规定为 “Bearer”+“ ”+token
        String Reltoken=JwtUtils.TOKEN_PREFIX+token;

        //设定返回响应的设置+带token
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");

        //带Token----放在响应头里
        response.setHeader("token",Reltoken);

    }

    //验证失败后的自动执行
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.getWriter().write("认证失败, 原因: " + failed.getMessage());
    }
}
