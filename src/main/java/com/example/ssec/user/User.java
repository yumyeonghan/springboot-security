package com.example.ssec.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Optional.ofNullable;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "provider")
    private String provider;

    @Column(name = "provider_id")
    private String providerId;

    @Column(name = "profile_image")
    private String profileImage;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

    protected User() {/*no-op*/}

    public User(String username, String provider, String providerId, String profileImage, Group group) {
        checkArgument(isNotEmpty(username), "username must be provided.");
        checkArgument(isNotEmpty(provider), "provider must be provided.");
        checkArgument(isNotEmpty(providerId), "providerId must be provided.");
        checkArgument(group != null, "group must be provided.");

        this.username = username;
        this.provider = provider;
        this.providerId = providerId;
        this.profileImage = profileImage;
        this.group = group;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getProvider() {
        return provider;
    }

    public String getProviderId() {
        return providerId;
    }

    public Optional<String> getProfileImage() {
        return ofNullable(profileImage);
    }

    public Group getGroup() {
        return group;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("id", id).append("username", username).append("provider", provider).append("providerId", providerId).append("profileImage", profileImage).toString();
    }

}
