package com.github.web3Auth.singlefactorauthtest;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.web3auth.singlefactorauth.SingleFactorAuth;
import com.github.web3auth.singlefactorauth.types.LoginParams;
import com.github.web3auth.singlefactorauth.types.SingleFactorAuthArgs;
import com.github.web3auth.singlefactorauth.types.TorusKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.auth0.jwt.algorithms.Algorithm;
import org.torusresearch.fetchnodedetails.types.TorusNetwork;
import com.github.web3Auth.singlefactorauthutils.JwtUtils;
import com.github.web3Auth.singlefactorauthutils.PemUtils;
import com.github.web3auth.singlefactorauth.types.TorusSubVerifierInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;

public class SingleFactorAuthTest {

    static SingleFactorAuth singleFactorAuth;
    static SingleFactorAuthArgs singleFactorAuthArgs;
    static LoginParams loginParams;
    static Algorithm algorithmRs;

    static String TEST_VERIFIER = "torus-test-health";
    static String TEST_VERIFIERID = "torus-test-health-aggregate";
    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        singleFactorAuthArgs = new SingleFactorAuthArgs(TorusNetwork.AQUA);
        singleFactorAuth = new SingleFactorAuth(singleFactorAuthArgs);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/com/github/web3Auth/singlefactorauth/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(),
                privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Test getTorusKey")
    @Test
    public void shouldGetTorusKey() throws ExecutionException, InterruptedException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        System.out.println("idToken: \n"+ idToken);
        loginParams = new LoginParams(TEST_VERIFIER, TEST_VERIFIERID, idToken,
                new TorusSubVerifierInfo[]{new TorusSubVerifierInfo(TEST_VERIFIER, idToken)});
        TorusKey torusKey = singleFactorAuth.getKey(loginParams).get();
        System.out.println(torusKey.getPrivateKey());
        BigInteger requiredPrivateKey = new BigInteger("f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d", 16);
        assert (requiredPrivateKey.equals(torusKey.getPrivateKey()));
        assertEquals("0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195", torusKey.getPublicAddress());
    }
}
