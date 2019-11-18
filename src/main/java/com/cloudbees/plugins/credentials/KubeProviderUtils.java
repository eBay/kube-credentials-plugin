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
package com.cloudbees.plugins.credentials;

import com.google.common.collect.ImmutableMap;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KubeProviderUtils {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(KubeProviderUtils.class.getName());


    public static Map getSecretStringDataOpenShiftUserPassword(Credentials credentials)
    {
        String userName = null;
        String passWord = null;
        Class cls = credentials.getClass();
        try {
            Method getUsername = cls.getMethod("getUsername");
            Method getPassword = cls.getMethod("getPassword");
            userName =  getUsername.invoke(credentials).toString();
            passWord =  getPassword.invoke(credentials).toString();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            LOGGER.log(Level.SEVERE, "exception using reflection ", e);
        }

        LOGGER.log(Level.FINE, "user name {0}", userName);
        LOGGER.log(Level.FINE, "password {0}", passWord);
        return ImmutableMap.of(KubeProviderConstants.OpenShiftBearerTokenCredentialImpl_userName, userName,
                KubeProviderConstants.OpenShiftBearerTokenCredentialImpl_password, passWord);
    }


    public static Map getSecretStringDataOpenShiftTokenCredentialImpl(Credentials credentials)
    {
        String secret = null;
        Class cls = credentials.getClass();
        try {
            Method getSecret = cls.getDeclaredMethod("getSecret");
            secret = getSecret.invoke(credentials).toString();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            LOGGER.log(Level.SEVERE, "exception using reflection ", e);
        }

        LOGGER.log(Level.FINE, "Secret content {0}", secret.toString());
        return ImmutableMap.of(KubeProviderConstants.OpenShiftTokenCredentialImplType_secret, secret);
    }



    public static Map getSecretStringData(Credentials credentials)
    {
        InputStream inputStream = null;
        String fileName = null;
        Class cls = credentials.getClass();
        try {
            Method getContent = cls.getDeclaredMethod("getContent");
            Method getFileName = cls.getDeclaredMethod("getFileName");
            inputStream = (InputStream) getContent.invoke(credentials);
            fileName = getFileName.invoke(credentials).toString();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            LOGGER.log(Level.SEVERE, "exception using reflection ", e);
        }

        StringBuffer content = new StringBuffer();
        try {
            int c;
            while((c = inputStream.read()) != -1)
            {
                content.append((char)c);
            }
        }catch (IOException e)
        {
            LOGGER.log(Level.SEVERE, "exception getting input stream for secret file ", e);
        }
        LOGGER.log(Level.FINE, "Secret content {0}", content.toString());
        LOGGER.log(Level.FINE, "file name {0}", fileName);
        return ImmutableMap.of(KubeProviderConstants.FileCredentialsImplType_fileName, fileName,
                KubeProviderConstants.FileCredentialsImplType_secretBytes, content.toString());
    }

    public static Map getSecretStringDataDockerServerCredential(Credentials credentials)
    {
        String clientKeysecret = null;
        String clientCertsecret = null;
        String clientServerCAsecret = null;
        Class cls = credentials.getClass();
        try {
            Method getClientKeySecret = cls.getMethod("getClientKey");
            clientKeysecret = getClientKeySecret.invoke(credentials).toString();

            Method getClientCertSecret = cls.getMethod("getClientCertificate");
            clientCertsecret = getClientCertSecret.invoke(credentials).toString();

            Method getServerCASecret = cls.getMethod("getServerCaCertificate");
            clientServerCAsecret = getServerCASecret.invoke(credentials).toString();


        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            LOGGER.log(Level.SEVERE, "exception using reflection ", e);
        }

        LOGGER.log(Level.FINE, "Secret content {0}", clientKeysecret.toString());

        LOGGER.log(Level.FINE, "Secret content {0}", clientCertsecret.toString());

        LOGGER.log(Level.FINE, "Secret content {0}", clientServerCAsecret.toString());

        return ImmutableMap.of(KubeProviderConstants.DockerServerCredentialType_clientKeySecret, clientKeysecret, KubeProviderConstants.DockerServerCredentialType_clientCertSecret,clientCertsecret, KubeProviderConstants.DockerServerCredentialType_serverCACertSecret, clientServerCAsecret);
    }

    public static Map getSecretStringServiceAccountCredential(Credentials credentials)
    {
        String id = null;
        Class cls = credentials.getClass();
        try {
            Method getId = cls.getMethod("getId");
            id =  getId.invoke(credentials).toString();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            LOGGER.log(Level.SEVERE, "exception using reflection ", e);
        }

        LOGGER.log(Level.FINE, "id {0}", id);
        return ImmutableMap.of(KubeProviderConstants.ServiceAccountCredential_id, id);
    }

    public static Map getSecretStringCredential(Credentials credentials)
    {
        String secret = null;
        Class cls = credentials.getClass();
        try {
            Method getId = cls.getMethod("getSecret");
            secret =  getId.invoke(credentials).toString();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            LOGGER.log(Level.SEVERE, "exception using reflection ", e);
        }

        LOGGER.log(Level.FINE, "secret {0}", secret);
        return ImmutableMap.of(KubeProviderConstants.StringCredentialsImpl_secretText, secret);
    }

    public static String getPrivateKeySourceUtil(Credentials credentials)
    {
        String privateKeySource = null;
        Class cls = credentials.getClass();
        try {
            Method getPrivateKeySource = cls.getMethod("getPrivateKeySource");
            privateKeySource =  getPrivateKeySource.invoke(credentials).getClass().getName();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            LOGGER.log(Level.SEVERE, "exception using reflection ", e);
        }
        return privateKeySource;
    }

    public static Map getSecretStringBasicUserPrivateKey(String credentialType, Credentials credentials)
    {
        Map map = null;
        Map<String, String> keyMap = new HashMap<>();

        if(credentialType.equals(KubeProviderConstants.BasicSSHUserPrivateKeyImplType_DirectEntry))
        {
            Class cls = credentials.getClass();
            List<String> privateKeys = null;
            String passPhrase = null;
            String user = null;

            int iterator = 0;

            try
            {
                Method getPassphrase = cls.getMethod("getPassphrase");

                if(getPassphrase.invoke(credentials) != null) {
                    passPhrase = getPassphrase.invoke(credentials).toString();
                    keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_passPhrase, passPhrase);
                }

                Method getUser = cls.getMethod("getUsername");
                user = getUser.invoke(credentials).toString();
                keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_user, user);

                Method getPrivateKeys = cls.getMethod("getPrivateKeys");
                privateKeys = (List<String>) getPrivateKeys.invoke(credentials);

                for(String str: privateKeys)
                {
                    keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_privateKey + Integer.valueOf(iterator), str);
                    iterator++;
                }

                keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_numKeys, Integer.toString(iterator));

            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                LOGGER.log(Level.SEVERE, "exception using reflection ", e);
            }

            map = new ImmutableMap.Builder().putAll(keyMap).build();

        }
        else if(credentialType.equals(KubeProviderConstants.BasicSSHUserPrivateKeyImplType_UserPrivateEntry))
        {
            Class cls = credentials.getClass();
            String passPhrase = null;
            String user = null;

            try
            {
                Method getPassphrase = cls.getMethod("getPassphrase");

                if(getPassphrase.invoke(credentials) != null) {
                    passPhrase = getPassphrase.invoke(credentials).toString();
                    keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_passPhrase, passPhrase);
                }

                Method getUser = cls.getMethod("getUsername");
                user = getUser.invoke(credentials).toString();
                keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_user, user);


            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                LOGGER.log(Level.SEVERE, "exception using reflection ", e);
            }

            LOGGER.log(Level.FINE, "user {0}", user);
            LOGGER.log(Level.FINE, "pass phrase {0}", passPhrase);

            map = new ImmutableMap.Builder().putAll(keyMap).build();

        }
        else if(credentialType.equals(KubeProviderConstants.BasicSSHUserPrivateKeyImplType_FileEntry))
        {
           Class cls = credentials.getClass();
           String keyFile = null;

           String passPhrase = null;
           String user = null;

           try
           {
               Method getPrivateKeySource = cls.getMethod("getPrivateKeySource");
               LOGGER.log(Level.FINE, "key source class {0}", getPrivateKeySource.invoke(credentials).getClass().getName());

               Class privateKeySourceCl =  getPrivateKeySource.invoke(credentials).getClass();
               LOGGER.log(Level.FINE, "privateKeySourceCl {0}", privateKeySourceCl.getName());

               Method getKeyFile = privateKeySourceCl.getMethod("getPrivateKeyFile");
               keyFile = getKeyFile.invoke(getPrivateKeySource.invoke(credentials)).toString();
               keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_keyStoreFile, keyFile);

               Method getPassphrase = cls.getMethod("getPassphrase");

               if(getPassphrase.invoke(credentials) != null) {
                   passPhrase = getPassphrase.invoke(credentials).toString();
                   keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_passPhrase, passPhrase);
               }

               Method getUser = cls.getMethod("getUsername");
               user = getUser.invoke(credentials).toString();
               keyMap.put(KubeProviderConstants.BasicSSHPrivateKeyImpl_user, user);

           } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
               LOGGER.log(Level.SEVERE, "exception using reflection ", e);
           }

           LOGGER.log(Level.FINE, "user {0}", user);
           LOGGER.log(Level.FINE, "keyfile {0}", keyFile);
           LOGGER.log(Level.FINE, "pass phrase {0}", passPhrase);

           map = new ImmutableMap.Builder().putAll(keyMap).build();

        }
        return map;
    }

}
