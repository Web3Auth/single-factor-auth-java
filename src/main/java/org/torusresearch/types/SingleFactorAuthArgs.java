package org.torusresearch.types;

import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.TorusNetwork;

import java.util.HashMap;

public class SingleFactorAuthArgs {

    public static HashMap<TorusNetwork, String> CONTRACT_MAP = new HashMap<TorusNetwork, String>() {{
        put(TorusNetwork.MAINNET, FetchNodeDetails.PROXY_ADDRESS_MAINNET);
        put(TorusNetwork.TESTNET, FetchNodeDetails.PROXY_ADDRESS_TESTNET);
        put(TorusNetwork.CYAN, FetchNodeDetails.PROXY_ADDRESS_CYAN);
        put(TorusNetwork.AQUA, FetchNodeDetails.PROXY_ADDRESS_AQUA);
    }};

    public static HashMap<TorusNetwork, String> SIGNER_MAP = new HashMap<TorusNetwork, String>() {{
        put(TorusNetwork.MAINNET, "https://signer.tor.us");
        put(TorusNetwork.TESTNET, "https://signer.tor.us");
        put(TorusNetwork.CYAN, "https://signer-polygon.tor.us");
        put(TorusNetwork.AQUA, "https://signer-polygon.tor.us");
    }};

    private TorusNetwork network;
    private String networkUrl;


    public SingleFactorAuthArgs(TorusNetwork network) {
        this.network = network;
    }

    public TorusNetwork getNetwork() {
        return network;
    }

    public void setNetwork(TorusNetwork network) {
        this.network = network;
    }

    public String getNetworkUrl() {
        return networkUrl;
    }

    public void setNetworkUrl(String networkUrl) {
        this.networkUrl = networkUrl;
    }
}
