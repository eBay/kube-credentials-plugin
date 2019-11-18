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
import com.cloudbees.plugins.credentials.SecretBytes;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import hudson.Extension;
import hudson.PluginManager;
import io.fabric8.kubernetes.api.model.Secret;
import jenkins.model.Jenkins;

import java.lang.reflect.Constructor;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SecretToCredentialConvertor that converts secret file.
 */
@Extension
public class SecretFileCredentialsConvertor extends SecretToCredentialConverter {

    private static final Logger LOG = Logger.getLogger(SecretFileCredentialsConvertor.class.getName());
    @Override
    public boolean canConvert(String type) {
        return KubeProviderConstants.FileCredentialsImplType.equals(type);
    }

    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {

        // check we have some data
        SecretUtils.requireNonNull(secret.getData(), "secretFile definition contains no data");

        String filenameBase64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.FileCredentialsImplType_fileName, "secretFile credential is missing the filename");

        String dataBase64 = SecretUtils.getNonNullSecretData(secret, KubeProviderConstants.FileCredentialsImplType_secretBytes, "secretFile credential is missing the data");

        String filename = SecretUtils.requireNonNull(SecretUtils.base64DecodeToString(filenameBase64), "secretFile credential has an invalid filename (must be base64 encoded UTF-8)");

        byte[] _data = SecretUtils.requireNonNull(SecretUtils.base64Decode(dataBase64), "secretFile credential has an invalid data (must be base64 encoded data)");

        SecretBytes sb = SecretBytes.fromBytes(_data);

        Object object = null;

        LOG.log(Level.FINE, "Converting secret file.");

        try {
            Class<?> secretFilempl = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl");
            Constructor<?> secretFileImplCtor = secretFilempl.getConstructor(CredentialsScope.class, String.class, String.class, String.class, SecretBytes.class);
            object = secretFileImplCtor.newInstance(CredentialsScope.GLOBAL,SecretUtils.getCredentialId(secret), SecretUtils.getCredentialDescription(secret), filename, sb);
            LOG.log(Level.FINE, "Created the object", object.toString());
        }catch (Exception e)
        {
            LOG.log(Level.SEVERE, "Error converting secret credential {0}.", e);
        }

        return (IdCredentials) object;
    }
}
