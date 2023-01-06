package com.example.springsecurity.config;



import com.example.springsecurity.security.CustomAccessDeniedHandler;
import com.example.springsecurity.security.CustomAuthenticationEntryPoint;
import com.example.springsecurity.security.CustomSecurityFilter;
import com.example.springsecurity.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // 스프링 Security 지원을 가능하게 함
@EnableGlobalMethodSecurity(securedEnabled = true) // @Secured 어노테이션 활성화
public class WebSecurityConfig {


    private final UserDetailsServiceImpl userDetailsService;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    @Bean // 비밀번호 암호화 기능 등록
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // h2-console 사용 및 resources 접근 허용 설정
        return (web) -> web.ignoring()
                //h2console, static의 css,js,이미지 등 인증처리 안하겠다
                .requestMatchers(PathRequest.toH2Console())
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // CSRF 설정
        http.csrf().disable();

        http.authorizeRequests().antMatchers("/api/user/**").permitAll()

                //위에서 인증처리 안하겠다고 선언한 것을 이렇게 할 수도 있음
//                .antMatchers("/h2-console/**").permitAll()
//                .antMatchers("/css/**").permitAll()
//                .antMatchers("/js/**").permitAll()
//                .antMatchers("/images/**").permitAll()
//                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()

                //위에서 제외된 url빼고는 전부 authentication 인증 처리를 하겠다.
                .anyRequest().authenticated();

        // Custom 로그인 페이지 사용
        http.formLogin().loginPage("/api/user/login-page").permitAll();
        // Custom Filter 등록하기
        http.addFilterBefore(new CustomSecurityFilter(userDetailsService, passwordEncoder()), UsernamePasswordAuthenticationFilter.class);
//        // 접근 제한 페이지 이동 설정
//        http.exceptionHandling().accessDeniedPage("/api/user/forbidden");
        // 401 Error 처리, Authorization 즉, 인증과정에서 실패할 시 처리
        http.exceptionHandling().authenticationEntryPoint(customAuthenticationEntryPoint);
        // 403 Error 처리, 인증과는 별개로 추가적인 권한이 충족되지 않는 경우
        http.exceptionHandling().accessDeniedHandler(customAccessDeniedHandler);
        return http.build();
    }

}