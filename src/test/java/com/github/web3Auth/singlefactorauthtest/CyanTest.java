package com.github.web3Auth.singlefactorauthtest;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.auth0.jwt.algorithms.Algorithm;
import com.github.web3Auth.singlefactorauthutils.JwtUtils;
import com.github.web3Auth.singlefactorauthutils.PemUtils;
import com.github.web3auth.singlefactorauth.SingleFactorAuth;
import com.github.web3auth.singlefactorauth.types.LoginParams;
import com.github.web3auth.singlefactorauth.types.SingleFactorAuthArgs;
import com.github.web3auth.singlefactorauth.types.TorusKey;
import com.github.web3auth.singlefactorauth.types.TorusSubVerifierInfo;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.types.TorusNetwork;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;

public class CyanTest {

    static SingleFactorAuth singleFactorAuth;
    static SingleFactorAuthArgs singleFactorAuthArgs;
    static LoginParams loginParams;
    static Algorithm algorithmRs;

    static String TEST_VERIFIER = "torus-test-health";
    static String TEST_AGGREGRATE_VERIFIER = "torus-test-health-aggregate";
    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        singleFactorAuthArgs = new SingleFactorAuthArgs(TorusNetwork.CYAN);
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
        loginParams = new LoginParams(TEST_VERIFIER, TORUS_TEST_EMAIL, idToken);
        TorusKey torusKey = singleFactorAuth.getKey(loginParams).get();
        BigInteger requiredPrivateKey = new BigInteger("44ca9a8ac5167ff11e0b48731f7bfde141fbbb0711d0abb54d5da554fb6fd40a", 16);
        assert (requiredPrivateKey.equals(torusKey.getPrivateKey()));
        assertEquals("0x1bbc291d4a8DCcb55fd969568D56b72a4BF62be8", torusKey.getPublicAddress());
    }

    @DisplayName("Test Aggregate getTorusKey")
    @Test
    public void shouldAggregrateGetTorusKey() throws ExecutionException, InterruptedException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        loginParams = new LoginParams(TEST_AGGREGRATE_VERIFIER, TORUS_TEST_EMAIL, idToken,
                new TorusSubVerifierInfo[]{new TorusSubVerifierInfo(TEST_VERIFIER, idToken)});
        TorusKey torusKey = singleFactorAuth.getKey(loginParams).get();
        BigInteger requiredPrivateKey = new BigInteger("66af498ea82c95d52fdb8c8dedd44cf2f758424a0eecab7ac3dd8721527ea2d4", 16);
        assert (requiredPrivateKey.equals(torusKey.getPrivateKey()));
        assertEquals("0xFF4c4A0Aa5D633302B5711C3047D7D5967884521", torusKey.getPublicAddress());
    }
}
