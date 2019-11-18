/*************************************************************
Modifications Copyright 2019 eBay Inc.
Author/Developer: Vasumathy Seenuvasan, Ravi Bukka, Murali Thirunagari

Original Copyright © 2011-2018, CloudBees, Inc.,	
Original License: https://github.com/jenkinsci/kubernetes-credentials-provider-plugin/blob/master/LICENSE.md
Author/Dveloper(s): Stephen Connolly

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
 ************************************************************/
package com.cloudbees.plugins.credentials.converters;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.KubeProviderConstants;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import hudson.Extension;
import io.fabric8.kubernetes.api.model.Secret;

import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class CertificateCredentialConvertorFileType extends SecretToCredentialConverter {

    private static final Logger LOG = Logger.getLogger(CertificateCredentialConvertorFileType.class.getName());

    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.CertificateCredentialsImplType_FileKeyStore.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "CertificateCredential definition contains no data");

        String keyStoreFile64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.CertificateCredentialsImpl_keyStoreFile, "CertificateCredential is missing the client key store file");

        String keyStorePassword64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.CertificateCredentialsImpl_keyStorePassword, "CertificateCredential is missing the key store password");

        String keyStoreFile = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(keyStoreFile64), "DockerServer credential  has an invalid client key (must be base64 encoded UTF-8)");

        String keyStorePassword = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(keyStorePassword64), "DockerServer credential  has an invalid server cert (must be base64 encoded UTF-8)");

        LOG.log(Level.FINE, "Converting CertificateCredential with file.");

        return new CertificateCredentialsImpl(CredentialsScope.GLOBAL, SecretUtils.getCredentialId(secret), SecretUtils.getCredentialDescription(secret), keyStorePassword, new CertificateCredentialsImpl.FileOnMasterKeyStoreSource(keyStoreFile));
    }
}
