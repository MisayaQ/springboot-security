package com.misaya.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @program: springboot-security
 * @description:
 * @version: 1.0
 * @author: LiuJiaQi
 * @create: 2021-01-31 18:27
 **/

//AOP
@EnableWebSecurity // 开启WebSecurity模式
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //链式编程
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 首页所有人可以访问 功能页只有对应的人才能访问
        // 请求授权的规则`
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限默认会去登录页面 需要开启登录页面
        //login
        http.formLogin()
                .usernameParameter("username")
                .passwordParameter("password")
                .loginProcessingUrl("/login")
                .loginPage("/toLogin");

        //开启了注销功能
        http.logout();

        //关闭csrf功能:跨站请求伪造,默认只能通过post方式提交logout请求
        http.csrf().disable();

        //注销成功返回首页
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能
        //定制记住我的参数！
        http.rememberMe().rememberMeParameter("remember");



    }

    //认证 springBoot 2.1.x可以使用
    //密码编码：PasswordEncoder
    //Spring security 5.0中新增了多种加密方式，也改变了密码的格式dd
    //要想我们的项目还能够正常登陆，需要修改一下configure中的代码。我们要将前端传过来的密 码进行某种方式加密
    // spring security 官方推荐的是使用bcrypt加密方式。
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //在内存中定义，也可以在jdbc中去拿....
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("jiaqi").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2", "vip3")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1", "vip2", "vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1", "vip2");
    }
}
