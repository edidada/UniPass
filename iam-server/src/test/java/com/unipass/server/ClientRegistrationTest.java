package com.unipass.server;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ClientRegistrationTest {
    private final RegisteredClientRepository clients=new InMemoryRegisteredClientRepository(RegisteredClient.withId("seed").clientId("seed")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://seed.example/cb").scope("openid").build());
    private ClientRegistrationService.Spec spec(String id,ClientRegistrationService.Kind kind,String callback) {
        return new ClientRegistrationService.Spec(id,"Test application",kind,List.of(callback),List.of(),Set.of("openid","api.read"));
    }
    @Test void confidentialClientStoresHashAndRequiresPkceAndRefreshRotation() {
        String secret="random-test-only-credential-0123456789";
        var service=new ClientRegistrationService(clients,false);
        service.register(spec("crm",ClientRegistrationService.Kind.CONFIDENTIAL,"https://crm.example/cb"),secret);
        var client=clients.findByClientId("crm");
        assertNotEquals(secret,client.getClientSecret());
        assertTrue(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(secret,client.getClientSecret()));
        assertTrue(client.getClientSettings().isRequireProofKey());
        assertFalse(client.getTokenSettings().isReuseRefreshTokens());
        assertTrue(client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
        assertThrows(IllegalStateException.class,()->service.register(spec("crm",ClientRegistrationService.Kind.CONFIDENTIAL,"https://crm.example/cb"),secret));
    }
    @Test void publicClientKindsHaveDifferentRefreshPolicyAndStrictCallbacks() {
        var service=new ClientRegistrationService(clients,false);
        service.register(spec("mobile",ClientRegistrationService.Kind.NATIVE,"com.example.mobile:/oauth/callback"),null);
        assertTrue(clients.findByClientId("mobile").getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
        service.register(spec("portal",ClientRegistrationService.Kind.SPA,"https://portal.example/callback"),null);
        assertFalse(clients.findByClientId("portal").getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
        for (String callback:List.of("http://public.example/cb","https://user:pass@rp.example/cb","https://rp.example/cb#fragment","app:/callback"))
            assertThrows(IllegalArgumentException.class,()->service.register(spec("invalid",ClientRegistrationService.Kind.NATIVE,callback),null));
        assertThrows(IllegalArgumentException.class,()->service.register(spec("weak",ClientRegistrationService.Kind.CONFIDENTIAL,"https://rp.example/cb"),"short"));
    }
}
