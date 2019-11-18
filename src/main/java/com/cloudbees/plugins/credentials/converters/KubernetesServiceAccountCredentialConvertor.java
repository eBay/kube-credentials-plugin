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
public class KubernetesServiceAccountCredentialConvertor extends SecretToCredentialConverter {

    private static final Logger LOG = Logger.getLogger(KubernetesServiceAccountCredentialConvertor.class.getName());

    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.ServiceAccountCredentialType.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "ServiceAccountCredential definition contains no data");

        String id64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.ServiceAccountCredential_id, "ServiceAccountCredential is missing the id");

        String id = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(id64), "ServiceAccountCredential has an invalid id (must be base64 encoded UTF-8)");

        LOG.log(Level.FINE, "Converting ServiceAccountCredential.");

        Object object = null;

        try {
            Class<?> kubernetesServiceAccount = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("org.csanchez.jenkins.plugins.kubernetes.ServiceAccountCredential");
            Constructor<?> kubernetesServiceAccountCtor = kubernetesServiceAccount.getConstructor(CredentialsScope.class, String.class, String.class);
            object = kubernetesServiceAccountCtor.newInstance(CredentialsScope.GLOBAL, id, SecretUtils.getCredentialDescription(secret));
            LOG.log(Level.FINE, "Created the object", object.toString());
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Error converting DockerServerCredential credential {0}.", e);
        }

        return (IdCredentials) object;
    }
}
