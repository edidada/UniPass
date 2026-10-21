package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class AuthenticationProofTest {
    private static final Instant NOW=Instant.parse("2026-10-21T00:00:00Z");
    private final UUID user=UUID.randomUUID();
    private IdentityPrincipal external(){return new IdentityPrincipal(user,5,NOW,List.of("ROLE_USER"),null,IdentityPrincipal.Method.FEISHU,null);}
    @Test void federatedLoginAndOtpNeverInventPasswordEvidence(){
        var principal=external();assertFalse(principal.hasRecentPassword(NOW));assertEquals(List.of("feishu"),principal.getAuthenticationMethods());
        var strong=principal.withMfa(NOW);assertFalse(strong.hasRecentPassword(NOW));assertEquals(List.of("feishu","otp"),strong.getAuthenticationMethods());
        assertNull(strong.getPasswordAuthenticatedAt());
    }
    @Test void passwordStepUpPreservesOriginalLoginAndFactorEvidence(){
        var principal=external().withMfa(NOW).withPassword(NOW.plusSeconds(60));
        assertEquals(NOW,principal.getAuthenticatedAt());assertEquals(NOW,principal.getMfaAt());
        assertEquals(user,principal.getUserId());assertEquals(5,principal.getEpoch());
        assertEquals(List.of("feishu","pwd","otp"),principal.getAuthenticationMethods());
        assertFalse(principal.hasRecentPassword(NOW));assertTrue(principal.hasRecentPassword(NOW.plusSeconds(60)));
        assertFalse(principal.hasRecentPassword(NOW.plusSeconds(360)));
    }
    @Test void normalDirectoryLoginRetainsPasswordAmrAndExactRecentBoundary(){
        var principal=new IdentityPrincipal(user,5,NOW,List.of("ROLE_USER"));
        assertEquals(List.of("pwd"),principal.getAuthenticationMethods());assertTrue(principal.hasRecentPassword(NOW.plusSeconds(299)));
        assertFalse(principal.hasRecentPassword(NOW.plusSeconds(300)));assertFalse(principal.hasRecentPassword(NOW.minusSeconds(1)));
    }
    @Test void newAndLegacyServerWrittenJsonRetainTheirAuthenticationMeaning()throws Exception{
        var mapper=new ObjectMapper().findAndRegisterModules();
        var restored=mapper.readValue(mapper.writeValueAsBytes(external().withMfa(NOW)),IdentityPrincipal.class);
        assertEquals(List.of("feishu","otp"),restored.getAuthenticationMethods());assertNull(restored.getPasswordAuthenticatedAt());
        var node=mapper.valueToTree(new IdentityPrincipal(user,5,NOW,List.of("ROLE_USER")));
        ((com.fasterxml.jackson.databind.node.ObjectNode)node).remove(List.of("authenticationMethod","passwordAuthenticatedAt"));
        var legacy=mapper.treeToValue(node,IdentityPrincipal.class);assertEquals(List.of("pwd"),legacy.getAuthenticationMethods());
        assertTrue(legacy.hasRecentPassword(NOW));
    }
    @Test void jdkSessionSerializationPreservesExternalProofAndRestoresAbsentLegacyFields()throws Exception{
        var external=roundTrip(external().withMfa(NOW));
        assertEquals(List.of("feishu","otp"),external.getAuthenticationMethods());assertNull(external.getPasswordAuthenticatedAt());
        var legacy=new IdentityPrincipal(user,5,NOW,List.of("ROLE_USER"));
        // Java serialization defaults fields absent from an older stream to null.
        for(String name:List.of("authenticationMethod","passwordAuthenticatedAt")){
            var field=IdentityPrincipal.class.getDeclaredField(name);field.setAccessible(true);field.set(legacy,null);
        }
        var restored=roundTrip(legacy);assertEquals(List.of("pwd"),restored.getAuthenticationMethods());
        assertEquals(NOW,restored.getPasswordAuthenticatedAt());assertFalse(restored.hasRecentPassword(NOW.plusSeconds(300)));
    }
    private static IdentityPrincipal roundTrip(IdentityPrincipal principal)throws Exception{
        var bytes=new java.io.ByteArrayOutputStream();
        try(var output=new java.io.ObjectOutputStream(bytes)){output.writeObject(principal);}
        try(var input=new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bytes.toByteArray()))){return (IdentityPrincipal)input.readObject();}
    }
}
