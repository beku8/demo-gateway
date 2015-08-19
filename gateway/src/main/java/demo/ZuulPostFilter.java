package demo;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

/**
 * This is a "post" zuul filter https://github.com/Netflix/zuul/wiki/How-it-Works 
 * @author beku
 *
 */
@Component
public class ZuulPostFilter extends ZuulFilter {

	private Logger logger = LoggerFactory.getLogger(ZuulPostFilter.class);
	private static String contextKey = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;
	
	@Autowired SessionRepository repository;
	
	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() {
		
		RequestContext context = RequestContext.getCurrentContext();
		
		context.getZuulResponseHeaders().forEach(pair -> {
			// Changes the returned Location header to gateway location. 
			// e.g: when DefaultSavedRequest is null & login page return http://localhost:9999/ as a default location.
			if("location".equalsIgnoreCase(pair.first())
					&& "http://localhost:9999/".equalsIgnoreCase(pair.second())){
				logger.debug("changing location header");
				pair.setSecond("http://localhost:8080/");
			}
			logger.debug("zuul response header {}:{}", pair.first(), pair.second());
		});
		
		// After the /uaa/login POST request returns HttpSession & SecurityContext are empty, this section fixes that.
		Cookie sessionCookie = WebUtils.getCookie(context.getRequest(), "SESSION");
		if(sessionCookie != null){
			HttpSession httpSession = context.getRequest().getSession();
			Session session = repository.getSession(httpSession.getId());
			
			if(httpSession.getAttribute(contextKey) == null && session.getAttribute(contextKey) != null){
				httpSession.setAttribute(contextKey, session.getAttribute(contextKey));
				SecurityContextHolder.setContext(session.getAttribute(contextKey));
				logger.debug("set security context for the httpSession: {}", SecurityContextHolder.getContext());
			}
			
		}
		
		return null;
	}

	@Override
	public String filterType() {
		return "post";
	}

	@Override
	public int filterOrder() {
		return 10;
	}
	

}
