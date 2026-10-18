package com.unipass.directory;

import java.util.Optional;

/** Credentials are request-scoped; implementations must never log or persist them. */
public interface DirectoryGateway {
    DirectoryConfig.Type type();
    Optional<DirectoryUser> findByStableId(String stableId);
    boolean verifyCredential(String stableId, char[] password);
    void changePassword(String stableId, char[] oldPassword, char[] newPassword);
    void disableUser(String stableId);

    record DirectoryUser(String stableId, String employeeNo, String dn, boolean disabled) { }
}
