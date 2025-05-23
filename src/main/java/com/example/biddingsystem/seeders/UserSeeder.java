package com.example.biddingsystem.seeders;

import com.example.biddingsystem.enums.Role;
import com.example.biddingsystem.models.UserEntity;
import com.example.biddingsystem.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class UserSeeder implements CommandLineRunner {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(UserSeeder.class);

    @Override
    public void run(String... args) throws Exception {
        seedUser();
    }

    public void seedUser() {
        logger.info("Seeding user data...");

        if (userRepository.findByEmail("admin@gmail.com").isEmpty()) {
            UserEntity adminUser = new UserEntity();
            adminUser.setEmail("admin@gmail.com");
            adminUser.setIsEnabled(true);
            adminUser.setFirstname("Admin");
            adminUser.setLastname("User");
            adminUser.setRole(Role.ADMIN);
            adminUser.setUsername("admin");
            adminUser.setPassword(passwordEncoder.encode("Securepassword123"));
            userRepository.save(adminUser);

            logger.info("User data seeded successfully.");
        } else {
            logger.info("Users already exist in the database. Skipping seeding");
        }
    }
}
