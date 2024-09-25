package org.example;

import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.request.filter.AbstractRequestFilter;
import org.apache.wicket.request.cycle.RequestCycle;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.engine.SecurityLogic;
import org.pac4j.core.config.Config;
import org.pac4j.core.profile.CommonProfile;
import org.apache.wicket.request.RequestHandlerStack.ReplaceHandlerException;
import org.apache.wicket.spring.injection.annot.SpringComponentInjector;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 4: Integrating Wicket
 * In your Wicket application, you would add a SpringComponentInjector to inject 
 * Spring beans (like the security configuration) and set up authentication checks.
 * 
 * @author tdiprima
 */
public class MyWicketApplication extends WebApplication {

    @Autowired
    private SecurityConfig securityConfig;

    @Override
    public void init() {
        super.init();

        // Spring component injector to inject beans
        getComponentInstantiationListeners().add(new SpringComponentInjector(this));

        // Setup Pac4j Security Filter
        setupPac4jSecurity();
    }

    private void setupPac4jSecurity() {
        Config pac4jConfig = securityConfig.pac4jConfig(); // Get pac4j JWT configuration

        // Set up a security logic instance
        SecurityLogic<Object, WebContext> securityLogic = new DefaultSecurityLogic<>();

        // Add request cycle listener to manage JWT validation and security logic
        getRequestCycleListeners().add(new AbstractRequestFilter() {
            @Override
            public void onRequestHandlerResolved(RequestCycle cycle, IRequestHandler handler) {
                WebContext webContext = new WicketWebContext(cycle); // Convert Wicket request to Pac4j WebContext

                try {
                    // Apply the security logic, validate JWT token, and authenticate the request
                    securityLogic.perform(webContext, pac4jConfig, (ctx, profiles, parameters) -> {
                        if (profiles.isEmpty()) {
                            throw new ReplaceHandlerException(getUnauthorizedPageHandler()); // Redirect to unauthorized page
                        }
                        return null;
                    }, null, "JwtAuthenticator", "JwtAuthorizer", null);
                } catch (Exception e) {
                    // Handle exceptions such as invalid or missing JWT
                    cycle.replaceHandler(getUnauthorizedPageHandler()); // Redirect to unauthorized page
                }
            }
        });
    }

    // This method returns a handler to redirect to an unauthorized page
    private IRequestHandler getUnauthorizedPageHandler() {
        return new RenderPageRequestHandler(new PageProvider(UnauthorizedPage.class));
    }

    // Set the home page for your Wicket application
    @Override
    public Class<? extends Page> getHomePage() {
        return HomePage.class;
    }
}
