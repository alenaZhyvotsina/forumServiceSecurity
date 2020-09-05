package telran.ashkelon2020.accounting.security.service;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.model.User;
import telran.ashkelon2020.forum.dao.ForumRepositoryMongoDB;
import telran.ashkelon2020.forum.model.Post;

@Service("customSecurity")  // name for bean
public class CustomWebSecurityService {
	
	@Autowired
	ForumRepositoryMongoDB forumRepository;
	
	@Autowired
	UserRepositoryMongoDB accountRepository;
	
	public boolean checkPostAuthority(String id, String user) {
		Post post = forumRepository.findById(id).orElse(null);
				
		return post == null ? true : post.getAuthor().equals(user);  // if ? false : - incorrect exception
	}
	
	public boolean isExpDateValid(Authentication authentication) {
		String login = authentication.getName();
		User user = accountRepository.findById(login).orElse(null);
		
		return user == null ? false : user.getExpDate().isAfter(LocalDateTime.now());
	}

}
