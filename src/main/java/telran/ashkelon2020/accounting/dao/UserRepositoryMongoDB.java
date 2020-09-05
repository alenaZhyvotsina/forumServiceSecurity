package telran.ashkelon2020.accounting.dao;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import telran.ashkelon2020.accounting.model.User;

public interface UserRepositoryMongoDB extends MongoRepository<User, String> {
	
	@Query("{{$binarySize: password}: {$lt: 4}}")
	public void deleteByPassword(String password);

}
