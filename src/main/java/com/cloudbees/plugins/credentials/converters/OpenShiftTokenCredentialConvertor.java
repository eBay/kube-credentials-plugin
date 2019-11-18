package com.cloudbees.plugins.credentials.converters;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.KubeProviderConstants;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import hudson.Extension;
import io.fabric8.kubernetes.api.model.Secret;
import jenkins.model.Jenkins;

import java.lang.reflect.Constructor;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class OpenShiftTokenCredentialConvertor extends SecretToCredentialConverter{

    private static final Logger LOG = Logger.getLogger(OpenShiftTokenCredentialConvertor.class.getName());
    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.OpenShiftTokenCredentialImplType.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "OpenShiftTokenCredential definition contains no data");

        String secretBase64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.OpenShiftTokenCredentialImplType_secret, "credential is missing the secret");

        String secretString = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(secretBase64), "credential has invalid secret (must be base64 encoded UTF-8)");

        LOG.log(Level.FINE, "Converting OpenShiftTokenCredentialConvertor.");

        Object object = null;

        try {
            Class<?> openShiftBearerTokenImpl = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("org.csanchez.jenkins.plugins.kubernetes.OpenShiftTokenCredentialImpl");
            Constructor<?> openShiftBearerTokenCtor = openShiftBearerTokenImpl.getConstructor(CredentialsScope.class, String.class, String.class, hudson.util.Secret.class);
            object = openShiftBearerTokenCtor.newInstance(CredentialsScope.GLOBAL,SecretUtils.getCredentialId(secret), SecretUtils.getCredentialDescription(secret), hudson.util.Secret.fromString(secretString));
            LOG.log(Level.FINE, "Created the object", object.toString());
        }catch (Exception e)
        {
            LOG.log(Level.SEVERE, "Error converting OpenShiftTokenCredentialConvertor credential {0}.", e);
        }

        return (IdCredentials) object;
    }
}
