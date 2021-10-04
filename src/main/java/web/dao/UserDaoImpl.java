package web.dao;

import org.springframework.stereotype.Repository;
import web.model.User;

import javax.persistence.EntityManager;
import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class UserDaoImpl implements UserDao {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public void saveUser(User user) {
        entityManager.merge(user);
    }

    @Override
    public void removeUser(User user) {
        entityManager.remove(user);
    }

    @Override
    public List<User> getAllUser() {
        return entityManager.createQuery("select u from User u", User.class).getResultList();
    }

    @Override
    public User findById(Long id) {
        User user = entityManager.find(User.class, id);
        if (user == null) {
            throw new EntityNotFoundException("Can't find user for id = " + id);
        }
        return user;
    }

    @Override
    public User findUserByName(String username) {

        User user = entityManager.createQuery(
                        "SELECT u FROM User u WHERE u.userName LIKE :username", User.class)
                .setParameter("username", username)
                .getResultList().stream().findFirst().orElse(null);
        if (user == null) {
            throw new EntityNotFoundException("Can't find user for username = " + username);
        }
        return user;
    }
}
