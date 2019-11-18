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
import hudson.Extension;
import io.fabric8.kubernetes.api.model.Secret;
import jenkins.model.Jenkins;

import java.lang.reflect.Constructor;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class DockerServerCredentialConvertor extends SecretToCredentialConverter {

    private static final Logger LOG = Logger.getLogger(DockerServerCredentialConvertor.class.getName());

    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.DockerServerCredentialType.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "DockerServerCredential definition contains no data");

        String clientKey64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.DockerServerCredentialType_clientKeySecret, "DockerServer credential is missing the client key");

        String clientCert64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.DockerServerCredentialType_clientCertSecret, "DockerServer credential is missing the client cert");

        String serverCACert64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.DockerServerCredentialType_serverCACertSecret, "DockerServer credential is missing the server cert");

        String clientKey = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(clientKey64), "DockerServer credential  has an invalid client key (must be base64 encoded UTF-8)");

        String clientCert = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(clientCert64), "DockerServer credential  has an invalid client cert (must be base64 encoded UTF-8)");

        String serverCACert = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(serverCACert64), "DockerServer credential  has an invalid server cert (must be base64 encoded UTF-8)");

        LOG.log(Level.FINE, "Converting DockerServerCredential.");

        Object object = null;

        try {
            Class<?> dockerServerCredentialImpl = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("org.jenkinsci.plugins.docker.commons.credentials.DockerServerCredentials");
            Constructor<?> dockerServerCredentialImplCtor = dockerServerCredentialImpl.getConstructor(CredentialsScope.class, String.class, String.class, hudson.util.Secret.class, String.class, String.class);
            object = dockerServerCredentialImplCtor.newInstance(CredentialsScope.GLOBAL, SecretUtils.getCredentialId(secret), SecretUtils.getCredentialDescription(secret), hudson.util.Secret.fromString(clientKey), clientCert, serverCACert);
            LOG.log(Level.FINE, "Created the object", object.toString());
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Error converting DockerServerCredential credential {0}.", e);
        }

        return (IdCredentials) object;
    }
}
