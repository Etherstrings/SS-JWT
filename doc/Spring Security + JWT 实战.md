

# Spring Security + JWT 实战

# 1.主要步骤

1.搭建基础的springboot工程，导入相关依赖

2.配置mysql，引用jpa

3.开启JPA支持

4.创建User实体，及controller,service,repository相关类

5.创建Jwt工具类，用于管理token相关的操作

6.创建JwtUser类，主要用于封装登录用户相关信息，例如用户名，密码，权限集合等，必须实现UserDetails 接口

7.创建JwtUserService 必须实现UserDetailsService，重写loadUserByUsername()方法，这样我们可以查询自己的数据库是否存在当前登录的用户名
9.创建拦截器，主要用于拦截用户登录信息，验证的事交给spring-security自己去做,验证成功会返回一个token,失败返回错误信息即可
10.用户验证成功过后会拿到token,下面的请求就需要携带这个token,后台需要一个新的拦截器进行权限验证
11.两个拦截器有了之后，只需要一个SecurityConfig将他们串联起来就行了

# 2.项目初始搭建

###### 1.项目结构

![img](https://img-blog.csdnimg.cn/20201106140837750.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTQ1MjQxNg==,size_16,color_FFFFFF,t_70#pic_center)

###### 2.Maven依赖

```java
	<properties>
		<java.version>1.8</java.version>
	</properties>

	<dependencies>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<!--springSecurity跟jwt的依赖-->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.security.oauth</groupId>
			<artifactId>spring-security-oauth2</artifactId>
			<version>2.3.5.RELEASE</version>
		</dependency>

		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt</artifactId>
			<version>0.9.1</version>
		</dependency>

		<!--添加jpa支持-->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>

		<!--mysql依赖包-->
		<dependency>
			<groupId>mysql</groupId>
			<artifactId>mysql-connector-java</artifactId>
		</dependency>

		<!--通过lombok包,实体类中不需要再写set,get方法,只需要添加一个@Data注解即可-->
		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<version>1.18.12</version>
			<scope>provided</scope>
		</dependency>
		
	</dependencies>

```

###### 3.Spring项目配置文件---application.properties

```java
#端口设置
server.port=8088

#数据库连接
spring.datasource.url=jdbc:mysql://localhost:3306/db01?characterEncoding=utf8&useUnicode=true&useSSL=false&serverTimezone=UTC
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.datasource.username=root
spring.datasource.password=123456

 jpa配置
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

```

###### 4.开启JPA---项目启动类加注解@EnableJpaRepositories

```java
@SpringBootApplication
@EnableJpaRepositories// 加一个这个注解即可开启JPA支持
public class Application {
    public static void main(String[] args) {
      SpringApplication.run(Application.class, args);
    }
}

```

###### 5.更新数据库----加入基础的User表

###### 6.编写User实体类

```java
@Entity
@Data // 注入该注解可以免去写set get方法
public class User {

    @Id
    @GeneratedValue
    private Integer id;

    private String username;

    private String password;

    private String role;

}

```

###### 7.编写repository层

```java
/**
 *   @Repository 必须加上
 *   必须继承  extends JpaRepository<User,Long>
 */
@Repository
public interface UserRepository extends JpaRepository<User,Long> {
	//JPA自带方法---不用写复杂的查询
    User save(User user);

    User findByUsername(String username);

    List<User> findAll();
}

```

###### 8.Service层及ServiceImpl

Service接口

```java
public interface UserServiceInterface {

    User save(User user);

    User findByUsername(String username);

    List<User> findAll();
}

```

Service接口实现类

```java
/**
 *  一定要加上 @Service 注解
 */
@Service
public class UserService implements UserServiceInterface {

    @Autowired
    UserRepository userRepository;

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }
}


```

###### 9.Controller层

    //Spring Security中的注解
    //进入方法前的自定义鉴权
    @PreAuthorize("hasAnyAuthority('ADMIN')")  //这一步很重要 拥有ADMIN权限的用户才能访问该请求
    
    //Spring Security中自带的密码加密解密类
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

```java
@RequestMapping("/user")
@RestController
public class UserController {

    @Autowired
    UserServiceInterface userServiceInterface;
    //Spring Security中自带的密码加密解密类
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping
    public User save(@RequestBody User parameter) {
        User user = new User();
        user.setUsername(parameter.getUsername());
        //这一步是加密密码--设置密码
        user.setPassword(bCryptPasswordEncoder.encode(parameter.getPassword()));
        
        //根据传入的用户名判断用户类别
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
    //Spring Security中的注解
    //进入方法前的自定义鉴权
    @PreAuthorize("hasAnyAuthority('ADMIN')")  //这一步很重要 拥有ADMIN权限的用户才能访问该请求
    public List<User> findAll(){
        return userServiceInterface.findAll();
    }

}

```

###### 10.@PreAuthorize注解

​	Spring Security提供的入方法之前的鉴权注解

```java
/**

    * 限制只能新增用户名称为david的用户

    */

   @PreAuthorize("#user.name.equals('david')")

   public void add(User user) {

  }
```

###### 11.工具类—JWT工具类

```java
/**
 * jwt 工具类 主要是生成token 检查token等相关方法
 */
public class JwtUtils {

    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    // TOKEN 过期时间
    public static final long EXPIRATION = 1000 * 60 * 30; // 三十分钟

    public static final String APP_SECRET_KEY = "secret";

    private static final String ROLE_CLAIMS = "rol";

    /**
     * 生成token
     *
     * @param username
     * @param role
     * @return
     */
    public static String createToken(String username, String role) {

        Map<String, Object> map = new HashMap<>();
        map.put(ROLE_CLAIMS, role);

        String token = Jwts
                .builder()
                .setSubject(username)
                .setClaims(map)
                .claim("username", username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION))
                .signWith(SignatureAlgorithm.HS256, APP_SECRET_KEY).compact();
        return token;
    }


    /**
     * 获取当前登录用户用户名
     *
     * @param token
     * @return
     */
    public static String getUsername(String token) {
        Claims claims = Jwts.parser().setSigningKey(APP_SECRET_KEY).parseClaimsJws(token).getBody();
        return claims.get("username").toString();
    }

    /**
     * 获取当前登录用户角色
     *
     * @param token
     * @return
     */
    public static String getUserRole(String token) {
        Claims claims = Jwts.parser().setSigningKey(APP_SECRET_KEY).parseClaimsJws(token).getBody();
        return claims.get("rol").toString();
    }

    /**
     * 获解析token中的信息
     *
     * @param token
     * @return
     */
    public static Claims checkJWT(String token) {
        try {
            final Claims claims = Jwts.parser().setSigningKey(APP_SECRET_KEY).parseClaimsJws(token).getBody();
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
        Claims claims = Jwts.parser().setSigningKey(APP_SECRET_KEY).parseClaimsJws(token).getBody();
        return claims.getExpiration().before(new Date());
    }


}
```

###### 12.JWT中Claims是什么----一个HashMap

​	所有主体信息都存在里面----用String-Object存

​	怎么取出来的 各个意思是什么？

​	1.设置解码秘钥

​	2.通过解密token

​	3.得到解密后的主体

```
Clamins  Jwts.parser().setSigningKey(JWT_SECRET_KEY).parseClaimsJws(token).getBody();
```

###### 13.UserDetails是什么？------Spring Security提供的实体类User

​	怎么用？

​	本身设定的主体实体类----比如我的User--继承该方法

​	**JwtUser Extends UserDetails**

​	重写其中的权限-用户名-用户密码方法

###### 14.UserDetailsService是什么？----------Spring Security提供的实体类的Service层

​	重写其中关键方法----通过username查询User

​	这里的User是被UserDetails包装后的安全类

###### 15.拦截器----用户登录（核心）

​	UsernamePasswordAuthenticationFilter----SpringSecurity提供的核心认证登录过滤器

​	同理 我的过滤器--继承此提供过滤器

```
JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter
```

​	1.此拦截器带的属性

```java
//认证管理器----里面存了认证的几种方式
private AuthenticationManager authenticationManager;
```

​	2.此拦截器的构造器

​	可以设置登录的请求是什么？

```java
    /**
     * security拦截默认是以POST形式走/login请求，我们这边设置为走/token请求
     * @param authenticationManager
     */
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager=authenticationManager;
        super.setFilterProcessesUrl("/token");
    }
```

​	3.过滤器中重写的方法---重点

###### 16.attemptAuthentication()方法----尝试认证方法

​	核心语句：AuthenticationManager的重要方法---authenticate()

```java
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginUser.getUsername(),loginUser.getPassword()) 
            );
```

​		此方法传入的是一个Authentication

​		返回的是一个通过认证后的权类

###### 17.Authentication

​		用户权限类----作为信息参数出现

​		

###### 18.authenticationManager.authenticate()方法

​	此方法为核心方法，可以通过选择提供的多种鉴权方式进行传入参数

​	返回的为Authentication通过校验后的用户权限类

###### 19.successfulAuthentication()方法----认证成功后自动执行的方法

​	目的:认证成功后在响应的响应头里带上Token

```java
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
```

###### 20.unsuccessfulAuthentication()---认证失败后自动执行方法

```java
response.getWriter().write("认证失败, 原因: " + failed.getMessage());
```

###### 21.@SneakyThrows注解

​	实际上就是不用写异常注释

###### 22.SecurityContextHolder是什么-----用户信息(核心)

​	SecurityContextHolder是SpringSecurity最基本的组件了，是用来存放SecurityContext的对象，默认是使用ThreadLocal实现的，这样就保证了本线程内所有的方法都可以获得SecurityContext对象

​	在`SecurityContextHolder`中保存的是当前访问者的信息。`Spring Security`使用一个`Authentication`对象来表示这个信息。

```java
// 获取安全上下文对象，就是那个保存在 ThreadLocal 里面的安全上下文对象
// 总是不为null(如果不存在，则创建一个authentication属性为null的empty安全上下文对象)
SecurityContext securityContext = SecurityContextHolder.getContext();
 
// 获取当前认证了的 principal(当事人),或者 request token (令牌)
// 如果没有认证，会是 null,该例子是认证之后的情况
Authentication authentication = securityContext.getAuthentication()
 
// 获取当事人信息对象，返回结果是 Object 类型，但实际上可以是应用程序自定义的带有更多应用相关信息的某个类型。
// 很多情况下，该对象是 Spring Security 核心接口 UserDetails 的一个实现类，你可以把 UserDetails 想像
// 成我们数据库中保存的一个用户信息到 SecurityContextHolder 中 Spring Security 需要的用户信息格式的
// 一个适配器。
Object principal = authentication.getPrincipal();
if (principal instanceof UserDetails) {
	String username = ((UserDetails)principal).getUsername();
} else {
	String username = principal.toString();


```

###### 23.JWTAuthorizationFilter---权限拦截器（重要）

​	JWTAuthorizationFilter extends BasicAuthenticationFilter

​	假如admin登录成功后，携带token去请求其他接口时，该拦截器会判断权限是否正确

```java
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
```

```java
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
```

###### 24.SecurityConfig(最重要)---Spring Security配置文件---决定怎么应用过滤器，哪些过滤，哪些不过滤

```java
/**
 * spring security配置
 *
 */
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 自定义用户认证逻辑
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 认证失败处理类
     */
    @Autowired
    private AuthenticationEntryPointImpl unauthorizedHandler;

    /**
     * 退出处理类
     */
    @Autowired
    private LogoutSuccessHandlerImpl logoutSuccessHandler;

    /**
     * token认证过滤器
     */
    @Autowired
    private JwtAuthenticationTokenFilter authenticationTokenFilter;

    /**
     * 跨域过滤器
     */
    @Autowired
    private CorsFilter corsFilter;

    /**
     * 解决 无法直接注入 AuthenticationManager
     *
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * 强散列哈希加密实现
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    /**
     * 身份认证接口
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //在这里关联数据库和security
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

    /**
     * anyRequest          |   匹配所有请求路径
     * access              |   SpringEl表达式结果为true时可以访问
     * anonymous           |   匿名可以访问
     * denyAll             |   用户不能访问
     * fullyAuthenticated  |   用户完全认证可以访问（非remember-me下自动登录）
     * hasAnyAuthority     |   如果有参数，参数表示权限，则其中任何一个权限可以访问
     * hasAnyRole          |   如果有参数，参数表示角色，则其中任何一个角色可以访问
     * hasAuthority        |   如果有参数，参数表示权限，则其权限可以访问
     * hasIpAddress        |   如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问
     * hasRole             |   如果有参数，参数表示角色，则其角色可以访问
     * permitAll           |   用户可以任意访问
     * rememberMe          |   允许通过remember-me登录的用户访问
     * authenticated       |   用户登录后可访问
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
    
        httpSecurity
                // CSRF禁用，因为不使用session
                .csrf().disable()
                // 认证失败处理类
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                // 基于token，所以不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // 过滤请求
                .authorizeRequests()
                // 对于登录login 验证码captchaImage 允许匿名访问
                .antMatchers("/login", "/captchaImage").anonymous()
                .antMatchers(
                        HttpMethod.GET,
                        "/*.html",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                ).permitAll()
                .antMatchers("/profile/**").permitAll()
                .antMatchers("/common/download**").permitAll()
                .antMatchers("/common/download/resource**").permitAll()
                .antMatchers("/swagger-ui.html").permitAll()
                .antMatchers("/swagger-resources/**").permitAll()
                .antMatchers("/webjars/**").permitAll()
                .antMatchers("/*/api-docs").permitAll()
                .antMatchers("/druid/**").permitAll()
                .antMatchers("/flowable/**").permitAll()
                .antMatchers("/socket/**").permitAll()
                .antMatchers("/api/common/**").permitAll()
                .antMatchers("/api/contract/**").permitAll()
                .antMatchers("/api/project/**").permitAll()
                .antMatchers("/api/document/**").permitAll()
                .antMatchers("/api/purchase/**").permitAll()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated()
                .and()
                .headers().frameOptions().disable();
        httpSecurity.logout().logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
        // 添加JWT filter
        httpSecurity.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        // 添加CORS filter
        httpSecurity.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class);
        httpSecurity.addFilterBefore(corsFilter, LogoutFilter.class);
    }

    /***
     * 核心过滤器配置方法
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }
}
```

###### 25. SecurityConfig extends WebSecurityConfigurerAdapter

​	1.传入JwtUserService来调用查询用户的方法

```java
    /**
     * 通过重写configure(),去数据库查询用户是否存在
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserService).passwordEncoder(bCryptPasswordEncoder());
    }
```

​	2.配置用哪些拦截器，怎么拦截？

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .authorizeRequests()
                // 以/user 开头的请求 都需要进行验证
                .antMatchers("/user/**")
                .authenticated()
                // 其他都放行了
                .anyRequest().permitAll()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager())) // 用户登录拦截
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))  // 权限拦截
                // 不需要session
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling();
    }
```

# 3.验证

1.配置SecurityConfig---关闭对于控制器的鉴权

  目的：为了能够创建admin和user用户

2.创建admin和user用户

​	admin由于传入的是admin---做了判断 Role自动赋值ADMIN

​	user赋值 USER

3.user向设定接口("/token")发送post请求

​	获取Token

4.无参数带user的Token向findeAll方法请求

​	可以调用

5.开启权限

6.无参数带User的Token向findAll发请求

​	被拒绝

7.admin获取Token

8.带admin的Token调用findALL

​	成功
