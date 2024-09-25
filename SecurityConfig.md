## SecurityConfig

To ensure that the `SecurityConfig` class is properly wired into your application, you need to integrate it with the framework you're using (e.g., Spring Boot, Shiro, etc.). The `SecurityConfig` class does more than just define the `jwtAuthenticator()` method &mdash; it also needs to be registered and used as part of the security configuration for your application.

### How SecurityConfig is Called:
1. **Spring Boot or Spring Security**:
   If you're using **Spring Boot** (or Spring Security), the `SecurityConfig` class should be annotated with `@Configuration`, and you would typically also define a `@Bean` for the `JwtAuthenticator`. Spring will detect this class automatically as part of the application context.

   Example in Spring Boot:
   
   ```java
   import org.springframework.context.annotation.Bean;
   import org.springframework.context.annotation.Configuration;
   import org.pac4j.core.config.Config;
   import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
   import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;

   @Configuration
   public class SecurityConfig {

       private String secret = "mySuperSecretKey";

       @Bean
       public JwtAuthenticator jwtAuthenticator() {
           JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
           jwtAuthenticator.addSignatureConfiguration(new SecretSignatureConfiguration(secret));
           return jwtAuthenticator;
       }

       @Bean
       public Config config(JwtAuthenticator jwtAuthenticator) {
           Config config = new Config(jwtAuthenticator);
           return config;
       }
   }
   ```

   In this case:
   
   - `@Configuration`: Tells Spring this class provides beans for the application context.
   - `@Bean`: Declares the `JwtAuthenticator` as a Spring Bean, which means it will be instantiated and managed by the Spring container.
   - The `Config` bean includes the `JwtAuthenticator` and would be used wherever the pac4j configuration is needed in the app.

2. **Apache Shiro**:
   If you're using **Shiro** without Spring, you need to make sure the `SecurityConfig` is loaded into Shiro's security manager or filter configuration.

   You'll need to ensure that the `SecurityManager` is correctly set up and that Shiro is using the pac4j authenticator. Here's an example of how you might integrate Shiro and pac4j:

   **Shiro configuration with pac4j**:
   
   ```java
   import org.apache.shiro.mgt.SecurityManager;
   import org.apache.shiro.web.env.EnvironmentLoaderListener;
   import org.apache.shiro.web.servlet.ShiroFilter;
   import org.pac4j.core.config.Config;
   import org.pac4j.core.context.session.SessionStore;
   import org.pac4j.core.engine.DefaultSecurityLogic;
   import org.pac4j.core.http.adapter.J2EHttpActionAdapter;

   public class ShiroPac4jSecurityConfig {
   
       public static SecurityManager configureShiroSecurity() {
           // Load your SecurityManager configuration here
           SecurityManager securityManager = new DefaultSecurityManager();

           // Set up your pac4j security logic, session store, etc.
           DefaultSecurityLogic<Object, J2EContext> securityLogic = new DefaultSecurityLogic<>();
           securityLogic.setConfig(pac4jConfig());
           
           return securityManager;
       }

       private static Config pac4jConfig() {
           JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
           jwtAuthenticator.addSignatureConfiguration(new SecretSignatureConfiguration("mySuperSecretKey"));

           return new Config(jwtAuthenticator);
       }
   }
   ```

   In a non-Spring Shiro setup, you'd integrate the security logic into your Shiro environment using the `SecurityManager`.

### Key Points:
- **Spring**: You define your `JwtAuthenticator` as a Spring Bean and register it via the application context. The security configuration (`SecurityConfig`) is automatically picked up because Spring scans for `@Configuration` classes. You can then inject the `JwtAuthenticator` or `Config` into other beans that need it.
- **Shiro**: You need to ensure your `SecurityManager` or Shiro filter integrates with pac4j by providing it with the `JwtAuthenticator` and handling the authentication flow.

### Is the jwtAuthenticator() method enough?
Simply defining the `jwtAuthenticator()` method isn't sufficient on its own unless it's correctly wired into your framework's security pipeline:

- **In Spring Boot**, the `SecurityConfig` class should also ensure that the authentication is applied to incoming HTTP requests, typically via security filters or by configuring Spring Security to use pac4j.
  
- **In Shiro**, you need to make sure the Shiro filter or security manager knows how to handle the `JwtAuthenticator` for processing requests and protecting resources.

### Example: Applying JWT Security in Spring Security:
In Spring Security, you would also define how the JWT authentication is applied to incoming requests, typically in an `HttpSecurity` configuration:

```java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private Config pac4jConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/**").authenticated()
            .and()
            .addFilter(new JwtTokenFilter(pac4jConfig)); // Add JWT filter here
    }
}
```

In this setup:

- The `JwtTokenFilter` would apply the `pac4j` configuration (which uses `JwtAuthenticator`) to requests.
- The `/api/**` endpoint would require JWT authentication, with other paths allowed to be accessed anonymously or with different security configurations.

### Summary:
- In **Spring Boot** or **Spring Security**, you need to annotate `SecurityConfig` with `@Configuration` and define a `@Bean` for `JwtAuthenticator`.
- In **Apache Shiro**, ensure that your `SecurityManager` or `ShiroFilter` is correctly configured to integrate with pac4j and use the `JwtAuthenticator`.

## What do you mean?

When I said **"you need to make sure the `SecurityConfig` is loaded into Shiro's security manager or filter configuration,"** I meant that in **Apache Shiro**, you need to explicitly tell Shiro to use the `JwtAuthenticator` as part of its security setup. Shiro doesn't automatically pick up configurations like Spring does, so you have to configure it manually.

Here's how you do it:

### Steps to Load SecurityConfig into Shiro:
1. **Create a Shiro `SecurityManager`**:
   You need to configure Shiro's `SecurityManager` to use the `JwtAuthenticator` that you’ve defined in the `SecurityConfig`.

2. **Register the Filter**:
   Shiro uses filters (like `AuthenticatingFilter`) to intercept requests. You need to ensure that your JWT-based filter is registered in the filter chain and that it uses the `JwtAuthenticator` from `SecurityConfig`.

### Example Configuration:

```java
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.servlet.ShiroFilter;

public class ShiroSecurityConfig {

    public DefaultSecurityManager configureSecurityManager(JwtAuthenticator jwtAuthenticator) {
        // Configure Shiro SecurityManager to use JWT Authenticator
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        
        // Add more configurations here as needed, such as Realm, SessionManager, etc.

        return securityManager;
    }

    public AbstractShiroFilter configureShiroFilter(DefaultSecurityManager securityManager, JwtTokenFilter jwtFilter) {
        // Create a Shiro filter and configure the filter chain
        FilterChainManager filterChainManager = new DefaultFilterChainManager();
        filterChainManager.addFilter("jwt", jwtFilter);

        // Apply the filter to protected URLs
        filterChainManager.createChain("/api/**", "jwt");

        PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
        chainResolver.setFilterChainManager(filterChainManager);

        ShiroFilter shiroFilter = new ShiroFilter();
        shiroFilter.setSecurityManager(securityManager);
        shiroFilter.setFilterChainResolver(chainResolver);

        return shiroFilter;
    }
}
```

### Key Points:
- **`DefaultSecurityManager`**: Shiro’s core class for managing security operations. You configure it to use your custom logic (e.g., JWT authentication).
- **`FilterChainManager`**: This manages Shiro’s filter chain, ensuring that certain filters (like your `JwtTokenFilter`) are applied to specific paths (like `/api/**`).

**In short**: You have to manually tell Shiro to use the `JwtAuthenticator` and apply it to incoming requests using filters in the `SecurityManager` and filter chain configuration.

<br>
