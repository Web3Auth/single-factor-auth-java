package org.torusresearch.singlefactorauth.types;

public class LoginParams {
    private final String verifier;
    private final String verifierId;
    private final String idToken;
    private TorusSubVerifierInfo[] subVerifierInfoArray;

    public LoginParams(String verifier, String verifierId, String idToken) {
        this.verifier = verifier;
        this.verifierId = verifierId;
        this.idToken = idToken;
    }

    public LoginParams(String verifier, String verifierId, String idToken, TorusSubVerifierInfo[] subVerifierInfoArray) {
        this.verifier = verifier;
        this.verifierId = verifierId;
        this.idToken = idToken;
        this.subVerifierInfoArray = subVerifierInfoArray;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getVerifierId() {
        return verifierId;
    }

    public String getIdToken() {
        return idToken;
    }

    public TorusSubVerifierInfo[] getSubVerifierInfoArray() {
        return subVerifierInfoArray;
    }
}
