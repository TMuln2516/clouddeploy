package config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Configuration
	public static class MySecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().antMatchers("/register-user/**", "/detail/**", "/register-employer/**").permitAll()
					.antMatchers("/user/**", "/search/**", "/job/**").hasAnyAuthority("USER", "ADMIN", "EMPLOYER")
					.antMatchers("/admin/**").hasAuthority("ADMIN").antMatchers("/employer/**", "/recruitment/**")
					.hasAuthority("EMPLOYER").anyRequest().permitAll().and().formLogin().loginPage("/login")
					.loginProcessingUrl("/doLogin").defaultSuccessUrl("/loginSuccess").failureUrl("/login?error=true")
					.and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/doLogout")).logoutSuccessUrl("/")
					.deleteCookies("JSESSIONID").and().csrf().disable();
		}
	}
}
