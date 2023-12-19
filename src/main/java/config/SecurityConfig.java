package config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import service.UserDetailsServiceImpl;

@Configuration
@EnableAutoConfiguration(exclude = SecurityAutoConfiguration.class)
@ComponentScan("service")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // Cho phép truy cập tất cả các tài nguyên tĩnh không bị kiểm soát bởi Spring Security
        web.ignoring().antMatchers("/static/**", "/css/**", "/js/**", "/images/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new EncodingFilter(), ChannelProcessingFilter.class);
        
        http.authorizeRequests()
            .antMatchers("/register-user/**", "/detail/**", "/register-employer/**").permitAll()
            .antMatchers("/user/**", "/search/**", "/job/**").hasAnyAuthority("USER", "ADMIN", "EMPLOYER")
            .antMatchers("/admin/**").hasAuthority("ADMIN")
            .antMatchers("/employer/**", "/recruitment/**").hasAuthority("EMPLOYER")
            .anyRequest().permitAll()
            .and()
            .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/doLogin")
                .defaultSuccessUrl("/loginSuccess")
                .failureUrl("/login?error=true")
            .and()
            .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/doLogout"))
                .logoutSuccessUrl("/")
                .deleteCookies("JSESSIONID")
            .and()
            .csrf().disable(); // Tạm thời vô hiệu hóa CSRF để đơn giản hóa ví dụ, bạn nên bật nó trong môi trường thực tế.
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
}
