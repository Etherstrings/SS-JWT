package com.wby.testsafe.safedemo.filter;

import com.wby.testsafe.safedemo.utils.JwtUtils;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

import static com.wby.testsafe.safedemo.utils.JwtUtils.TOKEN_HEADER;
import static com.wby.testsafe.safedemo.utils.JwtUtils.TOKEN_PREFIX;

/**
 * @description:
 * @author： wuboyu
 * @date： 2022-08-17 14:58
 */

//假如admin登录成功后，携带token去请求其他接口时，该拦截器会判断权限是否正确
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }


    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //在Header中
        //Authorization---对应Token
        //在Token中
        //TOKEN_PREFIX+token

        String tokenHeader = request.getHeader(TOKEN_HEADER);
        // 如果请求头中没有Authorization信息则直接放行了
        if(tokenHeader==null){
            chain.doFilter(request,response);
            return;
        }
        //如果取出来的Token不是以前缀开始的
        if(!tokenHeader.startsWith(TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }

        // 如果请求头中有token，则进行解析，并且设置认证信息
        //SecurityContextHolder线程共有当前信息类
        //getContext()---获取当前信息方法
        //setAuthentication()----设置当前的认证类
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(tokenHeader));
        super.doFilterInternal(request, response, chain);


    }
    // 这里从token中获取用户信息并新建一个token 就是上面说的设置认证信息
    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) throws Exception{
        //将Header中的带前缀的Token删除
        String token = tokenHeader.replace(JwtUtils.TOKEN_PREFIX, "");

        // 检测token是否过期 如果过期会自动抛出错误
        JwtUtils.isExpiration(token);
        String username = JwtUtils.getuserNameByJWT(token);
        String role = JwtUtils.getRoleByJWT(token);
        if (username != null) {
            return new UsernamePasswordAuthenticationToken(username, null,
                    Collections.singleton(new SimpleGrantedAuthority(role))
            );
        }
        return null;
    }
}
