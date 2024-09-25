package org.example;

import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.request.mapper.annotation.MountPath;

/**
 * Define UnauthorizedPage: You can create a simple Wicket page class that 
 * informs the user that they are not authorized.
 * 
 * @author tdiprima
 */
@MountPath("/unauthorized")
public class UnauthorizedPage extends WebPage {
    public UnauthorizedPage(PageParameters parameters) {
        super(parameters);
        add(new Label("message", "You are not authorized to access this page."));
    }
}
