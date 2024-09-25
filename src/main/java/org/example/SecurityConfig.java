package org.example;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.pac4j.core.config.Config;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.shiro.web.ShiroWebContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 2: Security Configuration
 * Configure pac4j, Shiro, and the JWT filter in your Spring Boot application.
 * This configuration will handle the authentication process.
 * 
 * @author tdiprima
 */
@Configuration
public class SecurityConfig {

    private static final String SECRET_KEY = "mySecretKey"; // Same secret as the JWT utility

    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(securityManager);
        factoryBean.setUnauthorizedUrl("/unauthorized");
        return factoryBean;
    }

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(iniRealm());
        return securityManager;
    }

    @Bean
    public IniRealm iniRealm() {
        return new IniRealm("classpath:shiro.ini");
    }

    @Bean
    public Config pac4jConfig() {
        JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
        jwtAuthenticator.addSignatureConfiguration(new SecretSignatureConfiguration(SECRET_KEY));

        Config config = new Config();
        config.setHttpActionAdapter((action, ctx) -> {
            ShiroWebContext shiroWebContext = (ShiroWebContext) ctx;
            SecurityUtils.getSubject().login(action.getCredentials());
            return null;
        });

        return config;
    }
}
