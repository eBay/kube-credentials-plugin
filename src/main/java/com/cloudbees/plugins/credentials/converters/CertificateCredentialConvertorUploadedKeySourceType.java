package com.cloudbees.plugins.credentials.converters;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.KubeProviderConstants;
import com.cloudbees.plugins.credentials.SecretBytes;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import hudson.Extension;
import io.fabric8.kubernetes.api.model.Secret;

import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class CertificateCredentialConvertorUploadedKeySourceType extends SecretToCredentialConverter {

    private static final Logger LOG = Logger.getLogger(CertificateCredentialConvertorFileType.class.getName());

    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.CertificateCredentialsImplType_UploadedKeyStore.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "CertificateCredential definition contains no data");

        String keyStoreBytes64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.CertificateCredentialsImpl_keyStoreBytes, "CertificateCredential is missing the client key bytes");

        String keyStorePassword64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.CertificateCredentialsImpl_keyStorePassword, "CertificateCredential is missing the key store password");

        String keyStoreBytes = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(keyStoreBytes64), "CertificateCredential has an invalid client key bytes (must be base64 encoded UTF-8)");

        String keyStorePassword = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(keyStorePassword64), "CertificateCredential  has an invalid key store password (must be base64 encoded UTF-8)");

        LOG.log(Level.FINE, "Converting CertificateCredential with bytes.");

        return new CertificateCredentialsImpl(CredentialsScope.GLOBAL, SecretUtils.getCredentialId(secret), SecretUtils.getCredentialDescription(secret), keyStorePassword, new CertificateCredentialsImpl.UploadedKeyStoreSource(SecretBytes.fromString(keyStoreBytes)));
    }
}
