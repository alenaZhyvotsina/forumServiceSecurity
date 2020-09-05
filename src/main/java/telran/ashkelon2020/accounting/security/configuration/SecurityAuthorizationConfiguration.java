package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(/*jsr250Enabled = true, securedEnabled = true, */prePostEnabled = true)
	// whereaver in project it is possible to make security method
	// here - in AccountingController:
	// @PreAuthorize("#login==authentication.name")
public class SecurityAuthorizationConfiguration extends WebSecurityConfigurerAdapter {
	
	//It works the first
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring()
			.antMatchers(HttpMethod.POST, "/account/register");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic(); // we work with Basic authentication
		http.csrf().disable();  // csrf - crosssite fault requests 
		
		http.authorizeRequests()
			//.anyRequest()
			//.permitAll();  // all requests are allowed (if not unthorized), 
						   // but if authorized - only with correct login/password
			//.authenticated();  // everything must be with authentication
			.antMatchers(HttpMethod.GET).permitAll()  // GET-requests - to all 
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**")
				.hasRole("ADMIN")
			.antMatchers("/account/login**", "/forum/post/{id}/like**")
				//.hasAnyRole("ADMIN", "MODERATOR", "USER")
				.access("@customSecurity.isExpDateValid(authentication) and hasAnyRole('ADMIN', 'MODERATOR', 'USER')")
			
				
			.antMatchers(HttpMethod.PUT, "/account/user/{login}**")
				.access("@customSecurity.isExpDateValid(authentication) and #login==authentication.name")
			.antMatchers(HttpMethod.DELETE, "/account/user/{login}**")
				.access("#login==authentication.name")
			
				
			.antMatchers(HttpMethod.POST, "/forum/post/{author}**")
				.access("#author==authentication.name "
						+ "and @customSecurity.isExpDateValid(authentication) "
						+ "and hasAnyRole('ADMIN', 'MODERATOR', 'USER')")
			.antMatchers(HttpMethod.PUT, "/forum/post/{id}**")
				.access("(@customSecurity.checkPostAuthority(#id, authentication.name) "
						+ "or hasRole('MODERATOR')) and @customSecurity.isExpDateValid(authentication)")
			.antMatchers(HttpMethod.DELETE, "/forum/post/{id}**")
				.access("(@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')) "
						+ "and @customSecurity.isExpDateValid(authentication)")
			.antMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}**")
				.access("#author==authentication.name "
						+ "and @customSecurity.isExpDateValid(authentication) "
						+ "and hasAnyRole('ADMIN', 'MODERATOR', 'USER')")
			
			.antMatchers("/account/password**")
				.authenticated()
			
			.anyRequest().authenticated();  
		
		
	}

}
