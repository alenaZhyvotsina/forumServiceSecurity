package telran.ashkelon2020.accounting.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import telran.ashkelon2020.accounting.dto.UserDto;
import telran.ashkelon2020.accounting.dto.UserNewDto;
import telran.ashkelon2020.accounting.dto.UserUpdDto;
import telran.ashkelon2020.accounting.service.UserService;

@RestController
@RequestMapping("/account")
public class AccountingController {
	
	@Autowired
	UserService userService;
		
	@PostMapping("/register")
	public UserDto addUser(@RequestBody UserNewDto userNewDto) {
		return userService.addUser(userNewDto);
	}
	
	@PostMapping("/login")
	public UserDto findUser(Authentication authentication) {	
		return userService.findUser(authentication.getName());
	}
	
	@DeleteMapping("/user/{login}")
	//@PreAuthorize("#login==authentication.name")
	public UserDto deleteUser(@PathVariable String login) {		
		return userService.deleteUser(login);
	}
	
	@PutMapping("/user/{login}")
	public UserDto updateUser(@PathVariable String login,
							  @RequestBody UserUpdDto userUpdDto) {		
		return userService.updateUser(login, userUpdDto);
	}
	
	@PutMapping("/user/{login}/role/{role}")
	public UserDto addRole(@PathVariable String login, @PathVariable String role) {			
		return userService.changeRoleList(login, role, true);		
	}
	
	@DeleteMapping("/user/{login}/role/{role}")
	public UserDto deleteRole(@PathVariable String login, @PathVariable String role) {
		
		return userService.changeRoleList(login, role, false);
	}
	
	@PutMapping("/password")
	public UserDto changePassword(@RequestHeader("X-Password") String newPassword,
					Authentication authentication) {
			
		return userService.changePassword(authentication.getName(), newPassword);
	}
	
}
