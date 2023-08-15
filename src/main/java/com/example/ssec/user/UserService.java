package com.example.ssec.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static org.hibernate.internal.util.StringHelper.isNotEmpty;

@Service
public class UserService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserRepository userRepository;

    private final GroupRepository groupRepository;

    public UserService(UserRepository userRepository, GroupRepository groupRepository) {
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        checkArgument(isNotEmpty(username), "username must be provided.");

        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
        checkArgument(isNotEmpty(provider), "provider must be provided.");
        checkArgument(isNotEmpty(providerId), "providerId must be provided.");

        return userRepository.findByProviderAndProviderId(provider, providerId);
    }


    @Transactional
    public User join(OAuth2User oauth2User, String authorizedClientRegistrationId) {
        checkArgument(oauth2User != null, "oauth2User must be provided.");
        checkArgument(isNotEmpty(authorizedClientRegistrationId), "authorizedClientRegistrationId must be provided.");

        String providerId = oauth2User.getName();
        return findByProviderAndProviderId(authorizedClientRegistrationId, providerId)
                .map(user -> {
                    log.warn("Already exists: {} for (provider: {}, providerId: {})", user, authorizedClientRegistrationId, providerId);
                    return user;
                })
                .orElseGet(() -> {
                    Map<String, Object> attributes = oauth2User.getAttributes();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
                    checkArgument(properties != null, "OAuth2User properties is empty");

                    String nickname = (String) properties.get("nickname"); //조금 애매하지만, 일단 이렇게 사용
                    String profileImage = (String) properties.get("profile_image");
                    Group group = groupRepository.findByName("USER_GROUP")
                            .orElseThrow(() -> new IllegalStateException("Could not found group for USER_GROUP"));
                    return userRepository.save(
                            new User(nickname, authorizedClientRegistrationId, providerId, profileImage, group)
                    );
                });
    }

}
