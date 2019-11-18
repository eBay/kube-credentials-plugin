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
public class StringCredentialConverter extends SecretToCredentialConverter  {

    private static final Logger LOG = Logger.getLogger(StringCredentialConverter.class.getName());

    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.StringCredentialsImplType.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "StringCredential definition contains no data");

        String secretText64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.StringCredentialsImpl_secretText, "StringCredential is missing the secret text");

        String secretText = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(secretText64), "StringCredential has an invalid secret text (must be base64 encoded UTF-8)");

        LOG.log(Level.FINE, "Converting StringCredential.");

        Object object = null;

        try {
            Class<?> stringCredential = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl");
            Constructor<?> stringCredentialCtor = stringCredential.getConstructor(CredentialsScope.class, String.class, String.class, hudson.util.Secret.class);
            object = stringCredentialCtor.newInstance(CredentialsScope.GLOBAL, SecretUtils.getCredentialId(secret), SecretUtils.getCredentialDescription(secret), hudson.util.Secret.fromString(secretText));
            LOG.log(Level.FINE, "Created the object", object.toString());
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Error converting StringCredential credential {0}.", e);
        }

        return (IdCredentials) object;
    }
}
