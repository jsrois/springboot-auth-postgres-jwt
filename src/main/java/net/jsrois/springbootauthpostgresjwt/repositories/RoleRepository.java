package net.jsrois.springbootauthpostgresjwt.repositories;

import net.jsrois.springbootauthpostgresjwt.models.ERole;
import net.jsrois.springbootauthpostgresjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}
