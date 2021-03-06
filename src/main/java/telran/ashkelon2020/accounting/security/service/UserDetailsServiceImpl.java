package telran.ashkelon2020.accounting.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.model.User;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	UserRepositoryMongoDB accountRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userAccount = accountRepository.findById(username)
							.orElseThrow(() -> new UsernameNotFoundException(username));
			
		String[] roles = userAccount.getRoles()
				.stream().map(r -> "ROLE_" + r.toUpperCase())
				.toArray(String[]::new);
		
		return new 
			org.springframework.security.core.userdetails.User(username, 
					userAccount.getPassword(), 
					AuthorityUtils.createAuthorityList(roles));
	}

}
