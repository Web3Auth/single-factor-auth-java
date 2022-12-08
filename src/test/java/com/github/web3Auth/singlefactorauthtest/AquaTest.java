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

public class AquaTest {

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
        loginParams = new LoginParams(TEST_VERIFIER, TORUS_TEST_EMAIL, idToken);
        TorusKey torusKey = singleFactorAuth.getKey(loginParams).get();
        BigInteger requiredPrivateKey = new BigInteger("d8204e9f8c270647294c54acd8d49ee208789f981a7503158e122527d38626d8", 16);
        assert (requiredPrivateKey.equals(torusKey.getPrivateKey()));
        assertEquals("0x8b32926cD9224fec3B296aA7250B049029434807", torusKey.getPublicAddress());
    }

    @DisplayName("Test Aggregate getTorusKey")
    @Test
    public void shouldAggregrateGetTorusKey() throws ExecutionException, InterruptedException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        loginParams = new LoginParams(TEST_AGGREGRATE_VERIFIER, TORUS_TEST_EMAIL, idToken,
                new TorusSubVerifierInfo[]{new TorusSubVerifierInfo(TEST_VERIFIER, idToken)});
        TorusKey torusKey = singleFactorAuth.getKey(loginParams).get();
        BigInteger requiredPrivateKey = new BigInteger("6f8b884f19975fb0d138ed21b22a6a7e1b79e37f611d0a29f1442b34efc6bacd", 16);
        assert (requiredPrivateKey.equals(torusKey.getPrivateKey()));
        assertEquals("0x62BaCa60f48C2b2b7e3074f7B7b4795EeF2afD2e", torusKey.getPublicAddress());
    }
}
