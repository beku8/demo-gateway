package demo;

import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.netflix.util.Pair;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

@Component
public class ZuulPreFilter extends ZuulFilter {

	private Logger logger = LoggerFactory.getLogger(ZuulPreFilter.class);
	
	@Autowired SessionRepository repository;
	
	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() {
		RequestContext context = RequestContext.getCurrentContext();
		
		HttpSession httpSession = context.getRequest().getSession();
		Session session = repository.getSession(httpSession.getId());
		//when you go directly to http://localhost:8080/uaa/login for the first time, session is not saved to the redis
		logger.debug("session before proxy: {}", session);
		
		DefaultCsrfToken csrfToken =  (DefaultCsrfToken)
				httpSession.getAttribute("org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN");
		if(session == null && csrfToken != null){
			//to let LoginApplication.csrfHeaderFilter to know the token. only useful first time direct access.
			context.addZuulRequestHeader("x-proxied-csrf", csrfToken.getToken());
		}
		
		return null;
	}
	

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return 10;
	}
	

}
