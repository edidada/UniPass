package com.unipass.server;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import java.net.URI;
import java.time.Duration;
import java.util.*;

/** Called by the offline operator CLI or the authorized APP_ADMIN management boundary. */
public final class ClientRegistrationService {
    public enum Kind { CONFIDENTIAL, NATIVE, SPA }
    public record Spec(@JsonProperty("client_id") String clientId, String name, Kind kind,
                       @JsonProperty("redirect_uris") List<String> redirects,
                       @JsonProperty("post_logout_redirect_uris") List<String> logoutRedirects,
                       Set<String> scopes, @JsonProperty("backchannel_logout_uri") String backchannel,
                       @JsonProperty("owner") String owner) {
        public Spec(String clientId,String name,Kind kind,List<String> redirects,List<String> logoutRedirects,Set<String> scopes){this(clientId,name,kind,redirects,logoutRedirects,scopes,null,null);}
        public Spec(String clientId,String name,Kind kind,List<String> redirects,List<String> logoutRedirects,Set<String> scopes,String backchannel){this(clientId,name,kind,redirects,logoutRedirects,scopes,backchannel,null);}
    }
    /** Length/format contract shared by the CLI and the management boundary; owner is enforced by the caller when required. */
    public static final int OWNER_MIN = 4, OWNER_MAX = 200;
    private final RegisteredClientRepository clients;
    private final boolean localHttp;
    public ClientRegistrationService(RegisteredClientRepository clients, boolean localHttp) { this.clients=clients; this.localHttp=localHttp; }
    public String register(Spec spec, String secret) {
        validate(spec, false);
        if (clients.findByClientId(spec.clientId())!=null) throw new IllegalStateException("Client already registered");
        if (secret!=null && !secret.matches("[\\x21-\\x7e]{32,64}")) throw new IllegalArgumentException("Client secret must contain 32 to 64 printable ASCII characters");
        RegisteredClient client=builder(spec, secret==null?null:PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret));
        clients.save(client); return client.getId();
    }
    /** Full policy check for one specification; duplicates and malformed fields are rejected, never normalized. */
    public void validate(Spec spec, boolean requireOwner) {
        if (spec==null || spec.clientId()==null || !spec.clientId().matches("[A-Za-z0-9_.-]{3,100}") || spec.name()==null || spec.name().isBlank() || spec.name().length()>200
                || spec.kind()==null || spec.redirects()==null || spec.redirects().isEmpty() || spec.redirects().size()>10
                || spec.logoutRedirects()==null || spec.logoutRedirects().size()>10 || spec.scopes()==null || !spec.scopes().contains("openid")
                || !Set.of("openid","profile","email","api.read").containsAll(spec.scopes())) throw new IllegalArgumentException("Invalid client specification");
        requireDistinct(spec.redirects()); requireDistinct(spec.logoutRedirects());
        if (spec.owner()!=null && !validOwner(spec.owner())) throw new IllegalArgumentException("Invalid owner");
        if (requireOwner && !validOwner(spec.owner())) throw new IllegalArgumentException("Owner required");
        spec.redirects().forEach(value->validateRedirect(value,spec.kind())); spec.logoutRedirects().forEach(value->validateRedirect(value,spec.kind()));
        if(spec.backchannel()!=null){
            validateBackchannel(spec.backchannel(),spec.redirects(),spec.kind());
        }
    }
    static boolean validOwner(String owner) {
        return owner!=null && owner.length()>=OWNER_MIN && owner.length()<=OWNER_MAX && owner.codePoints().noneMatch(Character::isISOControl);
    }
    private static void requireDistinct(List<String> values) {
        if (new HashSet<>(values).size()!=values.size()) throw new IllegalArgumentException("Duplicate URI in callback list");
    }
    /** Assembles the registration from a validated specification; passwordEncoder may be null for public clients. */
    public RegisteredClient builder(Spec spec, String passwordEncoderResult) {
        var settings=ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false)
                .setting("unipass.native",spec.kind()==Kind.NATIVE)
                .setting("unipass.backchannel_logout_uri",spec.backchannel()==null?"":spec.backchannel());
        if (spec.owner()!=null) settings.setting("unipass.owner",spec.owner());
        var builder=RegisteredClient.withId(UUID.randomUUID().toString()).clientId(spec.clientId()).clientName(spec.name())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientSettings(settings.build())
                .tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofSeconds(60)).accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30)).reuseRefreshTokens(false).build());
        spec.redirects().forEach(builder::redirectUri); spec.logoutRedirects().forEach(builder::postLogoutRedirectUri); spec.scopes().forEach(builder::scope);
        if (spec.kind()==Kind.CONFIDENTIAL) {
            if (passwordEncoderResult==null) throw new IllegalArgumentException("Client secret must contain 32 to 64 printable ASCII characters");
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientSecret(passwordEncoderResult);
        } else builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        if (spec.kind()!=Kind.SPA) builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        return builder.build();
    }
    private void validateRedirect(String value,Kind kind) {
        if (value==null || value.length()>1000) throw new IllegalArgumentException("Invalid callback URI");
        URI uri=URI.create(value);
        boolean https="https".equals(uri.getScheme()) && uri.getHost()!=null;
        boolean loopback=localHttp && "http".equals(uri.getScheme()) && uri.getHost()!=null && Set.of("127.0.0.1","localhost","[::1]").contains(uri.getHost());
        boolean nativeScheme=kind==Kind.NATIVE && uri.getScheme()!=null && uri.getScheme().matches("[a-z][a-z0-9-]*(\\.[a-z0-9-]+)+") && uri.getPath()!=null && !uri.getPath().isBlank();
        if (uri.getUserInfo()!=null || uri.getFragment()!=null || !(https||loopback||nativeScheme)) throw new IllegalArgumentException("Invalid callback URI");
    }
    private void validateBackchannel(String value,List<String> callbacks,Kind kind){
        validateRedirect(value,kind);URI uri=URI.create(value);
        if(kind!=Kind.CONFIDENTIAL || uri.getRawQuery()!=null || !"/logout/backchannel".equals(uri.getRawPath())
                || callbacks.stream().map(URI::create).noneMatch(callback->Objects.equals(callback.getScheme(),uri.getScheme()) && Objects.equals(callback.getRawAuthority(),uri.getRawAuthority())))
            throw new IllegalArgumentException("Back-channel must use a registered confidential callback origin and the fixed logout path");
    }
}
