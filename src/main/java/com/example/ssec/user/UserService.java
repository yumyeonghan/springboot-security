package com.example.ssec.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByLoginId(username)
                .map(user ->
                        User.builder() //userdetails의 User
                                .username(user.getLoginId())
                                .password(user.getPasswd())
                                .authorities(user.getGroup().getAuthorities())
                                .build()
                )
                .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
    }
}
