package web.dao;

import org.springframework.stereotype.Repository;
import web.model.Role;

import javax.persistence.EntityManager;
import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class RoleDaoImpl implements RoleDao {

    @PersistenceContext
    EntityManager entityManager;

    @Override
    public Role findByName(String roleName) {
        Role role = entityManager.createQuery(
                        "SELECT r FROM Role r WHERE r.name LIKE :roleName", Role.class)
                .setParameter("roleName", roleName)
                .getSingleResult();
        if (role == null) {
            throw new EntityNotFoundException("Can't find role  = " + roleName);
        }
        return role;
    }

    @Override
    public List<Role> getAllRoles() {
        return entityManager.createQuery("select r from Role r", Role.class).getResultList();
    }
}
