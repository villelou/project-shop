package com.example.springsecurityapplication.config;
import com.example.springsecurityapplication.services.PersonDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig{
    private final PersonDetailService personDetailService;

    @Bean
    public PasswordEncoder getPasswordEncode(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // конфигурируем работу Spring Security
        //http.csrf().disable() // отключаем защиту от межсайтовой подделки запросов
        http
        .authorizeHttpRequests() // указываем что все страницы должны быть защищены аутентификацией
                // Указываем на то что страница /admin доступна пользователю с ролью ADMIN
                .requestMatchers("/admin").hasRole("ADMIN")
                // указывает что не аутентифицированные пользователи могут зайти на страницу аутентификации и на объект ошибки
                // с помощью permitAll указываем что не аутентифицированные пользователи могут заходит на перечисленные страницы
                .requestMatchers("/authentication", "/error", "/registration").permitAll()
                // указываем что для всех остальных страниц необходимо вызывать метод authenticated(), который открывает форму аутентификации
//              .anyRequest().authenticated()
                .requestMatchers("/authentication", "registration", "error", "/resources/**", "/static/**", "/css/**", "js/**", "/img/**", "/product", "/product/info/{id}", "/product/search").permitAll()
                .anyRequest().hasAnyRole("USER", "ADMIN")
                .and() // уакзывает что дальше настраивается аутентификация и соединяем ее с настройкой доступа
                .formLogin().loginPage("/authentication") // уакзывает какой url запрос будет отправляться при заходе на защищенные страницы
                .loginProcessingUrl("/process_login") // указываем на какой адрес будут отправляться данные с формы. Нам уже не нужно будет создавать метод в контроллере и обрабатвать данные с формы. Мы задали url по умолчанию для обработки формы аутентификации по средствам Spring Security. Spring Security будет ждать объект с формы аутентификации и затем сверять логин и пароль с данными в БД
                .defaultSuccessUrl("/person_account", true) // Указываем на какой url необходимо направить пользователя после успешной аутентификации. Вторым аргументом указывается true чтобы перенаправление шло в любом случае после успешной аутентификации
                .failureUrl("/authentication?error") // Указываем куда необходимо перенаправить пользователя при проваленной аутентификации. В запрос будет передан объект error, который будет проверяться на форме и при наличии данного объекта в запросе выводится сообщение "Неправильный логин или пароль"
                .and()
                .logout().logoutUrl("/logout").logoutSuccessUrl("/authentication");
            return http.build();
    }
    @Autowired
    public SecurityConfig(PersonDetailService personDetailService) {
        this.personDetailService = personDetailService;
    }

//  private final AuthenticationProvider authenticationProvider;

//   public SecurityConfig(AuthenticationProvider authenticationProvider) {
//      this.authenticationProvider = authenticationProvider;
//  }
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
       // authenticationManagerBuilder.authenticationProvider(authenticationProvider);
    authenticationManagerBuilder.userDetailsService(personDetailService)
        .passwordEncoder(getPasswordEncode());
    }
}
