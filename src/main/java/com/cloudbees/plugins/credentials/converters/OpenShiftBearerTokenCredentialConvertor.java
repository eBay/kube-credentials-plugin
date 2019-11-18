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
public class OpenShiftBearerTokenCredentialConvertor extends SecretToCredentialConverter {

    private static final Logger LOG = Logger.getLogger(OpenShiftBearerTokenCredentialConvertor.class.getName());
    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.OpenShiftBearerTokenCredentialImplType.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "OpenShiftBearerTokenCredential definition contains no data");

        String usernameBase64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.OpenShiftBearerTokenCredentialImpl_userName, "OpenShiftBearerTokenCredential credential is missing the username");

        String passwordBase64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.OpenShiftBearerTokenCredentialImpl_password, "OpenShiftBearerTokenCredential credential is missing the password");

        String username = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(usernameBase64), "OpenShiftBearerTokenCredential credential has an invalid username (must be base64 encoded UTF-8)");

        String password = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(passwordBase64), "OpenShiftBearerTokenCredential credential has an invalid password (must be base64 encoded UTF-8)");

        LOG.log(Level.FINE, "Converting OpenShiftBearerTokenCredential.");

        Object object = null;

        try {
            Class<?> openShiftBearerTokenImpl = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("org.csanchez.jenkins.plugins.kubernetes.OpenShiftBearerTokenCredentialImpl");
            Constructor<?> openShiftBearerTokenCtor = openShiftBearerTokenImpl.getConstructor(CredentialsScope.class, String.class, String.class, String.class, String.class);
            object = openShiftBearerTokenCtor.newInstance(CredentialsScope.GLOBAL,SecretUtils.getCredentialId(secret), SecretUtils.getCredentialDescription(secret), username, password);
            LOG.log(Level.FINE, "Created the object", object.toString());
        }catch (Exception e)
        {
            LOG.log(Level.SEVERE, "Error converting OpenShiftBearerTokenCredential credential {0}.", e);
        }

        return (IdCredentials) object;
    }
}
