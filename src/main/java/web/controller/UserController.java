package web.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import web.model.Role;
import web.model.User;
import web.service.RoleService;
import web.service.UserService;

import java.util.List;
import java.util.Map;

@Controller
public class UserController {
    private final UserService userService;
    private final RoleService roleService;

    public UserController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping("/index")
    public String indexPage() {
        return "index";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String showAdminPage(ModelMap model) {
        model.addAttribute("users", userService.getAllUser());
        return "admin";
    }

    @GetMapping("/user")
    public String showUserPage(ModelMap model, @AuthenticationPrincipal User user) {
        model.addAttribute("user", userService.findUserByName(user.getUsername()));
        return "user";
    }

    @GetMapping("/user/add")
    public String showNewUserForm(ModelMap model) {
        model.addAttribute("user", new User());
        return "addUser";
    }

    @PostMapping("/admin")
    public String addUser(@ModelAttribute("user") User user, ModelMap model, BindingResult bindingResult) {

        if(bindingResult.hasErrors()){
            model.addAttribute("bindingResult", bindingResult.getAllErrors());
            return "addUser";
        }

        if (userService.getAllUser()
                .stream()
                .anyMatch(u -> u.getUsername().equals(user.getUsername()))) {
            model.addAttribute("loginError", "Login already exists, please choose another login");
            return "addUser";
        }

        if (user.getPassword() != null && !user.getPassword().equals(user.getPasswordConfirm())) {
            model.addAttribute("passwordError", "Passwords are different");
            return "addUser";
        }

        userService.saveUser(user);
        return "redirect:/admin";
    }

    @GetMapping("/user/update/{id}")
    @ResponseBody
    public User updateUserForm(@PathVariable("id") Long id) {
        User userFromDB = userService.findById(id);
        return userFromDB;
    }

    @PostMapping("/user/update")
    public String updateUser(User user,
                             @RequestParam Map<String, String> form) {
        List<Role> roles = roleService.getAllRoles();

        for (String key : form.values()) {
            if (roles.stream().anyMatch(role -> role.getName().equals(key))) {
                user.getRoles().add(roleService.findByName(key));
            }
        }
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        userService.saveUser(user);
        return "redirect:/admin";
    }

    @GetMapping("/user/remove")
    public String removeUser( @RequestParam Map<String, String> map) {
        String id1 = map.get("id1");
        Long id = Long.valueOf(id1);
        User userFromDB = userService.findById(id);
        userService.removeUser(userFromDB);
        return "redirect:/admin";
    }
}
