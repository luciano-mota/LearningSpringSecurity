package com.spring.security.jwt.controller;

import com.spring.security.jwt.dto.Login;
import com.spring.security.jwt.dto.Sessao;
import com.spring.security.jwt.model.User;
import com.spring.security.jwt.repository.UserRepository;
import com.spring.security.jwt.security.JWTCreator;
import com.spring.security.jwt.security.JWTObject;
import com.spring.security.jwt.security.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
public class LoginController {

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private SecurityConfig securityConfig;

    @Autowired
    private UserRepository repository;

    @PostMapping("/login")
    public Sessao logar(@RequestBody Login login) {
        User user = repository.findByUsername(login.getUsername());
        if (user != null) {
            boolean passwordOk = encoder.matches(login.getPassword(), login.getUsername());
            if (!passwordOk) {
                throw new RuntimeException("Senha inválida para o login: " + login.getUsername());
            }
            Sessao sessao = new Sessao();
            sessao.setLogin(login.getUsername());

            JWTObject jwtObject = new JWTObject();
            jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
            jwtObject.setExpiration(new Date(System.currentTimeMillis() + securityConfig.getExpiration()));
            jwtObject.setRoles(user.getRoles());
            sessao.setToken(JWTCreator.create(securityConfig.getPrefix(), securityConfig.getKey(), jwtObject));
            return sessao;
        } else {
            throw new RuntimeException("Erro ao tentar fazer login");
        }
    }
}
