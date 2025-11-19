package tt.gov.verifytt;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;

import java.util.Objects;

import io.mosip.vciclient.VCIClient;
import io.mosip.vciclient.constants.CredentialFormat;
import io.mosip.vciclient.credentialResponse.CredentialResponse;
import io.mosip.vciclient.dto.IssuerMetaData;
import io.mosip.vciclient.proof.jwt.JWTProof;


public class InjiVciClientModule extends ReactContextBaseJavaModule {
    private VCIClient vciClient;

    public InjiVciClientModule(@Nullable ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @ReactMethod
    public void init(String appId) {
        Log.d("InjiVciClientModule", "Initializing InjiVciClientModule with " + appId);
        vciClient = new VCIClient(appId);
    }

    @NonNull
    @Override
    public String getName() {
        return "InjiVciClient";
    }

    @ReactMethod
    public void requestCredential(ReadableMap issuerMetaData, String jwtProofValue, String accessToken, Promise promise) {
        Log.d("InjiVciClientModule", "requestCredential called");
        Log.d("InjiVciClientModule", "issuerMetaData: " + issuerMetaData);
        Log.d("InjiVciClientModule", "jwtProofValue: " + jwtProofValue);
        Log.d("InjiVciClientModule", "accessToken: " + accessToken);
        try {
            IssuerMetaData constructedIssuerMetadata ;
            String issuerMetadataCredentialFormat = issuerMetaData.getString("credentialFormat");
            Log.d("InjiVciClientModule", "credentialFormat: " + issuerMetadataCredentialFormat);
            Log.d("InjiVciClientModule", "Raw issuerMetaData credentialAudience: " + issuerMetaData.getString("credentialAudience"));
            Log.d("InjiVciClientModule", "Raw issuerMetaData credentialEndpoint: " + issuerMetaData.getString("credentialEndpoint"));
            if(Objects.equals(issuerMetadataCredentialFormat, CredentialFormat.LDP_VC.getValue())){
                constructedIssuerMetadata =  new IssuerMetaData(
                        issuerMetaData.getString("credentialAudience"),
                        issuerMetaData.getString("credentialEndpoint"),
                        issuerMetaData.getInt("downloadTimeoutInMilliSeconds"),
                        convertReadableArrayToStringArray(issuerMetaData.getArray("credentialType")),
                        CredentialFormat.LDP_VC,null,null);
                Log.d("InjiVciClientModule", "constructedIssuerMetadata (LDP_VC): " + constructedIssuerMetadata);

            } else if (Objects.equals(issuerMetadataCredentialFormat, CredentialFormat.MSO_MDOC.getValue())) {
                constructedIssuerMetadata =  new IssuerMetaData(
                        issuerMetaData.getString("credentialAudience"),
                        issuerMetaData.getString("credentialEndpoint"),
                        issuerMetaData.getInt("downloadTimeoutInMilliSeconds"),
                        null,
                        CredentialFormat.MSO_MDOC, issuerMetaData.getString("doctype"),
                        issuerMetaData.getMap("claims").toHashMap());
                Log.d("InjiVciClientModule", "constructedIssuerMetadata (MSO_MDOC): " + constructedIssuerMetadata);
                Log.d("InjiVciClientModule", "constructedIssuerMetadata (LDP_VC): " +
                        "credentialAudience=" + constructedIssuerMetadata.getCredentialAudience() +
                        ", credentialEndpoint=" + constructedIssuerMetadata.getCredentialEndpoint() +
                        ", timeout=" + constructedIssuerMetadata.getDownloadTimeoutInMilliSeconds() +
                        ", format=" + constructedIssuerMetadata.getCredentialFormat() +
                        ", credentialType=" + java.util.Arrays.toString(constructedIssuerMetadata.getCredentialType()));
            } else {
                Log.e("InjiVciClientModule", "Unexpected credentialFormat: " + issuerMetadataCredentialFormat);
                throw new IllegalStateException("Unexpected value: " + issuerMetadataCredentialFormat);
            }

            Log.d("InjiVciClientModule", "Creating JWTProof");
            JWTProof jwtProof = new JWTProof(jwtProofValue);
            Log.d("InjiVciClientModule", "JWTProof created");
            Log.d("InjiVciClientModule", "Calling vciClient.requestCredential");


            Log.d("InjiVciClientModule", "constructedIssuerMetadata (LDP_VC): " +
                    "credentialAudience=" + constructedIssuerMetadata.getCredentialAudience() +
                    ", credentialEndpoint=" + constructedIssuerMetadata.getCredentialEndpoint() +
                    ", timeout=" + constructedIssuerMetadata.getDownloadTimeoutInMilliSeconds() +
                    ", format=" + constructedIssuerMetadata.getCredentialFormat() +
                    ", credentialType=" + java.util.Arrays.toString(constructedIssuerMetadata.getCredentialType()));


            CredentialResponse response = vciClient.requestCredential(constructedIssuerMetadata, jwtProof, accessToken);
            Log.d("InjiVciClientModule", "CredentialResponse: " + response.toJsonString());
            promise.resolve(response.toJsonString());
        } catch (Exception exception) {
            Log.e("InjiVciClientModule", "Exception in requestCredential", exception);
            promise.reject(exception);
        }
    }

    private String[] convertReadableArrayToStringArray(ReadableArray readableArray) {
        String[] stringArray = new String[readableArray.size()];
        for (int i = 0; i < readableArray.size(); i++) {
            stringArray[i] = readableArray.getString(i);
        }
        return stringArray;
    }
}
