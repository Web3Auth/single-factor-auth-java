package com.github.web3auth.singlefactorauth;

import com.github.web3auth.singlefactorauth.types.*;
import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.NodeDetails;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.helpers.Utils;
import org.torusresearch.torusutils.types.*;
import org.web3j.crypto.Hash;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class SingleFactorAuth {

    public final FetchNodeDetails nodeDetailManager;
    public final TorusUtils torusUtils;

    public SingleFactorAuth(SingleFactorAuthArgs singleFactorAuthArgs) {
        if (Utils.isEmpty(singleFactorAuthArgs.getNetworkUrl())) {
            this.nodeDetailManager = new FetchNodeDetails(singleFactorAuthArgs.getNetwork(), SingleFactorAuthArgs.CONTRACT_MAP.get(singleFactorAuthArgs.getNetwork()));
        } else {
            this.nodeDetailManager = new FetchNodeDetails(singleFactorAuthArgs.getNetworkUrl(), SingleFactorAuthArgs.CONTRACT_MAP.get(singleFactorAuthArgs.getNetwork()));
        }

        TorusCtorOptions opts = new TorusCtorOptions("single-factor-auth-java");
        opts.setEnableOneKey(true);
        opts.setNetwork(singleFactorAuthArgs.getNetwork().toString());
        opts.setSignerHost(SingleFactorAuthArgs.SIGNER_MAP.get(singleFactorAuthArgs.getNetwork()) + "/api/sign");
        opts.setAllowHost(SingleFactorAuthArgs.SIGNER_MAP.get(singleFactorAuthArgs.getNetwork()) + "/api/allow");
        this.torusUtils = new TorusUtils(opts);
    }

    public CompletableFuture<TorusKey> getKey(LoginParams loginParams) throws ExecutionException, InterruptedException {
        NodeDetails details = this.nodeDetailManager.getNodeDetails(loginParams.getVerifier(), loginParams.getVerifierId()).get();
        TorusPublicKey pubDetails = torusUtils.getUserTypeAndAddress(details.getTorusNodeEndpoints(), details.getTorusNodePub(), new VerifierArgs(loginParams.getVerifier(), loginParams.getVerifierId()), true).get();
        if (pubDetails.getUpgraded()) {
            CompletableFuture<TorusKey> response = new CompletableFuture<>();
            response.completeExceptionally(new Exception("User has already enabled MFA"));
            return response;
        }
        if (pubDetails.getTypeOfUser().equals(TypeOfUser.v1)) {
            torusUtils.getOrSetNonce(pubDetails.getX(), pubDetails.getY(), false).get();
        }
        RetrieveSharesResponse retrieveSharesResponse;

        if (loginParams.getSubVerifierInfoArray() != null && loginParams.getSubVerifierInfoArray().length > 0) {
            TorusSubVerifierInfo[] subVerifierInfoArray = loginParams.getSubVerifierInfoArray();
            AggregateVerifierParams aggregateVerifierParams = new AggregateVerifierParams();
            aggregateVerifierParams.setVerify_params(new AggregateVerifierParams.VerifierParams[subVerifierInfoArray.length]);
            aggregateVerifierParams.setSub_verifier_ids(new String[subVerifierInfoArray.length]);
            List<String> aggregateIdTokenSeeds = new ArrayList<>();
            String aggregateVerifierId = "";
            for (int i = 0; i < subVerifierInfoArray.length; i++) {
                TorusSubVerifierInfo userInfo = subVerifierInfoArray[i];
                String finalToken = userInfo.getIdToken();
                aggregateVerifierParams.setVerifyParamItem(new AggregateVerifierParams.VerifierParams(loginParams.getVerifierId(), finalToken), i);
                aggregateVerifierParams.setSubVerifierIdItem(userInfo.getVerifier(), i);
                aggregateIdTokenSeeds.add(finalToken);
                aggregateVerifierId = loginParams.getVerifierId();
            }
            Collections.sort(aggregateIdTokenSeeds);
            String aggregateTokenString = String.join(Character.toString((char) 29), aggregateIdTokenSeeds);
            String aggregateIdToken = Hash.sha3String(aggregateTokenString).substring(2);
            aggregateVerifierParams.setVerifier_id(aggregateVerifierId);
            HashMap<String, Object> aggregateVerifierParamsHashMap = new HashMap<>();
            aggregateVerifierParamsHashMap.put("verify_params", aggregateVerifierParams.getVerify_params());
            aggregateVerifierParamsHashMap.put("sub_verifier_ids", aggregateVerifierParams.getSub_verifier_ids());
            aggregateVerifierParamsHashMap.put("verifier_id", aggregateVerifierParams.getVerifier_id());
            details = this.nodeDetailManager.getNodeDetails(loginParams.getVerifier(), aggregateVerifierId).get();
            retrieveSharesResponse = torusUtils.retrieveShares(details.getTorusNodeEndpoints(), details.getTorusIndexes(), loginParams.getVerifier(), aggregateVerifierParamsHashMap, aggregateIdToken).get();
        } else {
            HashMap<String, Object> verifierParams = new HashMap<>();
            verifierParams.put("verifier_id", loginParams.getVerifierId());
            retrieveSharesResponse = torusUtils.retrieveShares(details.getTorusNodeEndpoints(), details.getTorusIndexes(), loginParams.getVerifier(), verifierParams, loginParams.getIdToken()).get();
        }
        CompletableFuture<TorusKey> torusKeyCompletableFuture = new CompletableFuture<>();
        if (retrieveSharesResponse.getPrivKey() == null) {
            torusKeyCompletableFuture.completeExceptionally(new Exception("Unable to get private key from torus nodes"));
        }
        torusKeyCompletableFuture.complete(new TorusKey(retrieveSharesResponse.getPrivKey(), retrieveSharesResponse.getEthAddress()));
        return torusKeyCompletableFuture;
    }
}