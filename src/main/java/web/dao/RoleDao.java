package web.dao;

import web.model.Role;

import java.util.List;

public interface RoleDao {

    Role findByName(String roleName);

    List<Role> getAllRoles();
}
