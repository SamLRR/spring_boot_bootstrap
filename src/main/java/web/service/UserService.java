package web.service;

import web.model.User;

import java.util.List;

public interface UserService {

    void saveUser(User user);

    void removeUser(User user);

    List<User> getAllUser();

    User findById(Long id);

    User findUserByName(String username);
}
