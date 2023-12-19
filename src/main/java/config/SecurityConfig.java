package config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
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
@EnableWebSecurity
@ComponentScan("service")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/register-user/**").permitAll()
            .antMatchers("/detail/**").permitAll()
            .antMatchers("/register-employer/**").permitAll()
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
            .csrf();
    }
}
