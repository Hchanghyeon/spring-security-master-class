package com.prgrms.devcourse.user;

import java.util.NoSuchElementException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
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
                        User.builder()
                                .username(user.getLoginId())
                                .password(user.getPasswd())
                                .authorities(user.getGroup().getAuthorities())
                                .build()
                )
                .orElseThrow(() -> new NoSuchElementException("찾는 아이디가 없습니다."));
    }
}
