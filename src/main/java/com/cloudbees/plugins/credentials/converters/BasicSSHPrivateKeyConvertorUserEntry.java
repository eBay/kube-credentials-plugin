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
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class BasicSSHPrivateKeyConvertorUserEntry  extends SecretToCredentialConverter{

    private static final Logger LOG = Logger.getLogger(BasicSSHPrivateKeyConvertorUserEntry.class.getName());

    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.BasicSSHUserPrivateKeyImplType_UserPrivateEntry.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        SecretUtils.requireNonNull(secret.getData(), "BasicSSHPrivateKey definition contains no data");

        String user64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.BasicSSHPrivateKeyImpl_user, "Basic SSH Key is missing the user");

        Optional<String> optionalPassphrase64 = SecretUtils.getOptionalSecretData(secret, KubeProviderConstants.BasicSSHPrivateKeyImpl_passPhrase, "Basic SSH Key is missing the pass phrase");

        String user = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(user64), "Basic SSH Key  has an invalid user (must be base64 encoded UTF-8)");

        String passphrase = null;

        if (optionalPassphrase64.isPresent()) {
            passphrase = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(optionalPassphrase64.get()), "Basic SSH Key  has an invalid user (must be base64 encoded UTF-8)");
        }

        LOG.log(Level.FINE, "Converting BasicSSHPrivateKey with user entry.");

        Object object = null;
        Object keySourceObject = null;

        try {

            Class privateKeySource = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$PrivateKeySource");

            Class<?> keySource = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$UsersPrivateKeySource");
            Constructor<?> keySourceCtor = keySource.getConstructor();
            keySourceObject = keySourceCtor.newInstance();

            Class<?> basicSSHPrivateKeyImpl = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey");
            Constructor<?> basicSSHPrivateKeyImplCtor = basicSSHPrivateKeyImpl.getConstructor(CredentialsScope.class, String.class, String.class, privateKeySource, String.class, String.class);
            object = basicSSHPrivateKeyImplCtor.newInstance(CredentialsScope.GLOBAL, SecretUtils.getCredentialId(secret), user, keySourceObject , passphrase, SecretUtils.getCredentialDescription(secret));

            LOG.log(Level.FINE, "Created the object", object.toString());
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Error converting BasicSSHPrivateKey with user entry credential {0}.", e);
        }

        return (IdCredentials) object;
    }
}
