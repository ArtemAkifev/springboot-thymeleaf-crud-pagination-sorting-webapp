package net.javaguides.springboot.config;

import net.javaguides.springboot.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //кастомная реализация HttpSecurity http
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()   // защита от csrf угроз
                .authorizeRequests()    //авторизовать запрос след. образом
                //.antMatchers("/login").permitAll()
                .antMatchers(HttpMethod.GET, "/**").hasAnyRole(Role.USER.name())
                .antMatchers(HttpMethod.POST, "/**").hasAnyRole(Role.USER.name())
                .antMatchers(HttpMethod.DELETE, "/**").hasAnyRole(Role.USER.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/")
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))  //c Get на Post б
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .logoutSuccessUrl("/login")
        ;
    }


    @Bean
    @Override
    protected UserDetailsService userDetailsService() {

        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("user")
                        .password("$2a$12$AWj.PVj/u4u.66.EfGGCLOIO35lvBqUrVOxAn0lCtQrxkMHCXyYiq")
                        //.password(passwordEncoder().encode("user"))
                        .roles(Role.USER.name())
                        .build()
        );
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
