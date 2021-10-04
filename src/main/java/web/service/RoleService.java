package web.service;


import web.model.Role;

import java.util.List;

public interface RoleService {

    Role findByName(String roleName);

    List<Role> getAllRoles();
}
