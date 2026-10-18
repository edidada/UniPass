package com.unipass.server;

import com.fasterxml.jackson.annotation.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.io.Serializable;
import java.time.Instant;
import java.util.*;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonIgnoreProperties(ignoreUnknown = true)
public final class IdentityPrincipal implements UserDetails, Serializable {
    private static final long serialVersionUID=1L;
    private final UUID userId;
    private final long epoch;
    private final Instant authenticatedAt;
    private final List<String> roles;
    private final Instant mfaAt;
    public IdentityPrincipal(UUID userId,long epoch,Instant authenticatedAt,List<String> roles) { this(userId,epoch,authenticatedAt,roles,null); }
    @JsonCreator public IdentityPrincipal(@JsonProperty("userId") UUID userId, @JsonProperty("epoch") long epoch,
            @JsonProperty("authenticatedAt") Instant authenticatedAt, @JsonProperty("roles") List<String> roles, @JsonProperty("mfaAt") Instant mfaAt) {
        this.userId = userId; this.epoch = epoch; this.authenticatedAt = authenticatedAt; this.roles = new ArrayList<>(roles);
        this.mfaAt=mfaAt;
    }
    public UUID getUserId() { return userId; }
    public long getEpoch() { return epoch; }
    public Instant getAuthenticatedAt() { return authenticatedAt; }
    public List<String> getRoles() { return new ArrayList<>(roles); }
    public Instant getMfaAt() { return mfaAt; }
    public IdentityPrincipal withMfa(Instant at) { return new IdentityPrincipal(userId,epoch,authenticatedAt,roles,at); }
    @Override @JsonIgnore public String getUsername() { return userId.toString(); }
    @Override @JsonIgnore public String getPassword() { return ""; }
    @Override @JsonIgnore public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream().map(SimpleGrantedAuthority::new).toList();
    }
    @Override public String toString() { return "IdentityPrincipal[" + userId + "]"; }
}
