package org.bmstu;

import javax.servlet.annotation.*;
import javax.servlet.*; 
import java.io.IOException;
import javax.servlet.http.*;
import java.util.*;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.PublicKey;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.URLEncoder;

@WebFilter(filterName= "jwt-filter")
public class JWTFilter implements Filter {

    final Logger logger = LoggerFactory.getLogger(Filter.class);
    private String COOKIE_NAME;
    private String LOGIN_PAGE;
    private String [] TRUSTED_HOSTS;
    private String SERVERPUBKEY;
    private PublicKey pubKey;
    private JwtParser parser;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        
        logger.info("init JWTFilter filter");
        LOGIN_PAGE = filterConfig.getInitParameter("loginPage");
        COOKIE_NAME = filterConfig.getInitParameter("cookieName");
        TRUSTED_HOSTS = filterConfig.getInitParameter("trustedHosts").split(" ");
        SERVERPUBKEY = filterConfig.getInitParameter("serverPubKey");

        try {
            byte[] keyBytes = IOUtils.toByteArray(this.getClass()
                                .getResourceAsStream(SERVERPUBKEY != null ? SERVERPUBKEY : "/pubkey.der"));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes); 
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pubKey = kf.generatePublic(spec);
            parser = Jwts.parser().setSigningKey(pubKey);
        } catch(Exception e) {
            logger.error("failed to read public key due to {}", e);
            throw new ServletException("failed to read public key", e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        logger.info("apply JWTFilter filter");

        if(Arrays.stream(TRUSTED_HOSTS)
                .filter(h -> h.equalsIgnoreCase(request.getRemoteHost()))
                .findFirst().isPresent()) {
            logger.info("host {} host is trusted {} bypassing checks",request.getRemoteHost(), TRUSTED_HOSTS);
            chain.doFilter(request, response);
            return;
        }
        
        StringBuffer REDIRECT_PAGE = new StringBuffer(((HttpServletRequest)request).getRequestURL());
        if(((HttpServletRequest)request).getQueryString() != null)
            REDIRECT_PAGE.append("?").append(((HttpServletRequest)request).getQueryString());

        if(((HttpServletRequest)request).getCookies() == null) {
            logger.info("no cookie {}", COOKIE_NAME);
            ((HttpServletResponse)response).sendRedirect(LOGIN_PAGE + "?back=" + URLEncoder.encode(REDIRECT_PAGE.toString()));
            return;
        }

        final Optional<Cookie> cookie = Arrays.stream(((HttpServletRequest)request).getCookies())
                                            .filter(c -> c.getName().equalsIgnoreCase(COOKIE_NAME)).findFirst();

        if(!cookie.isPresent()) {
            if(Arrays.stream(TRUSTED_HOSTS).filter(h -> h.equalsIgnoreCase(request.getRemoteHost())).findFirst().isPresent()) {
                logger.info("host {} host is trusted {} bypassing checks",request.getRemoteHost(), TRUSTED_HOSTS);
                chain.doFilter(request, response);
            } else {
                ((HttpServletResponse)response).sendRedirect(LOGIN_PAGE + "?back=" + URLEncoder.encode(REDIRECT_PAGE.toString()));
            }
        } else {
            try { 
                Claims claims = parser.parseClaimsJws(cookie.get().getValue()).getBody();
                Date today = new Date();
                if(today.after(claims.getExpiration()) || today.before(claims.getNotBefore())) {
                    logger.warn("cookie is outdated");
                    ((HttpServletResponse)response).sendRedirect(LOGIN_PAGE + "?back=" + URLEncoder.encode(REDIRECT_PAGE.toString()));
                    return;
                }
                logger.warn("got cookie " + claims.get("usr"));
                //if(((HttpServletRequest)request).getSession().hasAttrinbute("usr"))
                if(!claims.get("usr", Map.class).get("id").equals(
                    ((HttpServletRequest)request).getSession().getAttribute("usr-id"))) {

                    logger.info("User switched or empty. Invalidating session.");

                    ((HttpServletRequest)request).getSession().invalidate();
                    ((HttpServletRequest)request).getSession()
                        .setAttribute("usr", claims.get("usr"));
                    ((HttpServletRequest)request).getSession()
                        .setAttribute("usr-id", claims.get("usr", Map.class).get("id"));
                    ((HttpServletRequest)request).getSession()
                        .setAttribute("usr-name", claims.get("usr", Map.class).get("name"));
                }                
                chain.doFilter(request, response);
            } catch (SignatureException se) {
                logger.error("cookie validation failed due to {}", se);  
                ((HttpServletResponse)response).sendRedirect(LOGIN_PAGE 
                        + "?back=" + URLEncoder.encode(REDIRECT_PAGE.toString()));
            }
        }
    }

    @Override
    public void destroy() {

    }

}
