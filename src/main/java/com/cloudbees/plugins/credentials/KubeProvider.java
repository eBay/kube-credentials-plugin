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

import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.google.common.collect.ImmutableMap;
import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.api.model.SecretList;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.DefaultKubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
Class to define all constants needed for kube credential provider.
 */
public class KubeProvider {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(KubeProvider.class.getName());


    public static Secret storeSecret(Credentials credentials)
    {
        String credentialType = "";
        Map secretStringData = null;

        LOGGER.log(Level.FINE, "Is secret Username password? {0}", credentials instanceof UsernamePasswordCredentialsImpl);
        LOGGER.log(Level.FINE, "Is secret file? {0}", credentials.getClass().getName().contains("FileCredentialsImpl"));
        LOGGER.log(Level.FINE, "Credentials class name: {0}", credentials.getClass().getName());
        LOGGER.log(Level.FINE, "Credentials ID : {0}", ((BaseStandardCredentials)credentials).getId());


        if(credentials.getClass().getName().contains(KubeProviderConstants.FileCredentialsImplType))
        {
            credentialType = KubeProviderConstants.FileCredentialsImplType;
            secretStringData = KubeProviderUtils.getSecretStringData(credentials);
        }
        else if(credentials.getClass().getName().contains(KubeProviderConstants.OpenShiftBearerTokenCredentialImplType))
        {
            credentialType = KubeProviderConstants.OpenShiftBearerTokenCredentialImplType;
            secretStringData = KubeProviderUtils.getSecretStringDataOpenShiftUserPassword(credentials);
        }
        else if(credentials.getClass().getName().contains(KubeProviderConstants.OpenShiftTokenCredentialImplType))
        {
            credentialType = KubeProviderConstants.OpenShiftTokenCredentialImplType;
            secretStringData = KubeProviderUtils.getSecretStringDataOpenShiftTokenCredentialImpl(credentials);
        }
        else if(credentials.getClass().getName().contains(KubeProviderConstants.DockerServerCredentialType))
        {
            credentialType = KubeProviderConstants.DockerServerCredentialType;
            secretStringData = KubeProviderUtils.getSecretStringDataDockerServerCredential(credentials);
        }
        else if(credentials.getClass().getName().contains(KubeProviderConstants.ServiceAccountCredentialType))
        {
            credentialType = KubeProviderConstants.ServiceAccountCredentialType;
            secretStringData = KubeProviderUtils.getSecretStringServiceAccountCredential(credentials);
        }
        else if(credentials.getClass().getName().contains(KubeProviderConstants.StringCredentialsImplType))
        {
            credentialType = KubeProviderConstants.StringCredentialsImplType;
            secretStringData = KubeProviderUtils.getSecretStringCredential(credentials);
        }
        else if(credentials.getClass().getName().contains(KubeProviderConstants.BasicSSHUserPrivateKeyImplType))
        {
            if(KubeProviderUtils.getPrivateKeySourceUtil(credentials).contains(KubeProviderConstants.DirectEntryPrivateKeySource))
            {
                credentialType = KubeProviderConstants.BasicSSHUserPrivateKeyImplType_DirectEntry;
                secretStringData = KubeProviderUtils.getSecretStringBasicUserPrivateKey(credentialType, credentials);

            }
            else if(KubeProviderUtils.getPrivateKeySourceUtil(credentials).contains(KubeProviderConstants.FileOnMasterPrivateKeySource))
            {
                credentialType = KubeProviderConstants.BasicSSHUserPrivateKeyImplType_FileEntry;
                secretStringData = KubeProviderUtils.getSecretStringBasicUserPrivateKey(credentialType, credentials);

            }
            else if(KubeProviderUtils.getPrivateKeySourceUtil(credentials).contains(KubeProviderConstants.UsersPrivateKeySource))
            {
                credentialType = KubeProviderConstants.BasicSSHUserPrivateKeyImplType_UserPrivateEntry;
                secretStringData = KubeProviderUtils.getSecretStringBasicUserPrivateKey(credentialType, credentials);

            }
        }
        else if(credentials instanceof CertificateCredentialsImpl)
        {
            if(((CertificateCredentialsImpl) credentials).getKeyStoreSource() instanceof CertificateCredentialsImpl.FileOnMasterKeyStoreSource) {
                credentialType = KubeProviderConstants.CertificateCredentialsImplType_FileKeyStore;
                secretStringData = ImmutableMap.of(KubeProviderConstants.CertificateCredentialsImpl_keyStoreFile, ((CertificateCredentialsImpl.FileOnMasterKeyStoreSource) ((CertificateCredentialsImpl) credentials).getKeyStoreSource()).getKeyStoreFile(),
                        KubeProviderConstants.CertificateCredentialsImpl_keyStorePassword, ((CertificateCredentialsImpl) credentials).getPassword().getPlainText());
            }
            else if(((CertificateCredentialsImpl) credentials).getKeyStoreSource() instanceof CertificateCredentialsImpl.UploadedKeyStoreSource)
            {
                credentialType = KubeProviderConstants.CertificateCredentialsImplType_UploadedKeyStore;
                secretStringData = ImmutableMap.of(KubeProviderConstants.CertificateCredentialsImpl_keyStoreBytes, Arrays.toString(((CertificateCredentialsImpl.UploadedKeyStoreSource) ((CertificateCredentialsImpl) credentials).getKeyStoreSource()).getKeyStoreBytes()),
                        KubeProviderConstants.CertificateCredentialsImpl_keyStorePassword, ((CertificateCredentialsImpl) credentials).getPassword().getPlainText());
            }
        }
        else if(credentials instanceof UsernamePasswordCredentialsImpl) {
            credentialType = KubeProviderConstants.UsernamePasswordCredentialsImplType;
            secretStringData = ImmutableMap.of(KubeProviderConstants.UsernamePasswordCredentialsImpl_userName, ((UsernamePasswordCredentialsImpl) credentials).getUsername(),
                    KubeProviderConstants.UsernamePasswordCredentialsImpl_password, ((UsernamePasswordCredentialsImpl) credentials).getPassword().getPlainText());
        }

        ObjectMeta metadata = new ObjectMeta();

        LOGGER.log(Level.FINE, "credentials object - {0}", credentials);
        LOGGER.log(Level.FINE, "base credentials object - {0}", (BaseStandardCredentials)credentials);

        //handle empty for description because immutable is used
        String description = "";
        if(((BaseStandardCredentials)credentials).getDescription() != null){
            description = ((BaseStandardCredentials)credentials).getDescription();
        }

        metadata.setAnnotations(ImmutableMap.of(KubeProviderConstants.credentialDescription,
                description,KubeProviderConstants.credentialID, ((BaseStandardCredentials)credentials).getId()));
        String ciName = System.getenv(KubeProviderConstants.JENKINS_URL).substring(System.getenv(KubeProviderConstants.JENKINS_URL).lastIndexOf("/")+1);
        metadata.setLabels(ImmutableMap.of(KubeProviderConstants.credentialID,((BaseStandardCredentials)credentials).getId(),KubeProviderConstants.credentialType,credentialType,KubeProviderConstants.ciName,ciName));
        LOGGER.log(Level.FINE, "Secret to be stored ", ((BaseStandardCredentials)credentials).getId());

        String secretName = KubeCredentialNaming.generateName(UUID.randomUUID().toString(), ciName);
        metadata.setName(secretName);

        Secret kubeSecret = new SecretBuilder().withMetadata(metadata).withStringData(secretStringData).build();
        ConfigBuilder cb = new ConfigBuilder();
        Config config = cb.build();
        DefaultKubernetesClient _client = new DefaultKubernetesClient(config);
        LOGGER.log(Level.FINE, "kube namespace - {0}", _client.getNamespace());
        Secret jenkinsSecret = null;
        try {
            jenkinsSecret = _client.secrets().inNamespace("ciaas").create(kubeSecret);
        }catch(KubernetesClientException kce){
            LOGGER.log(Level.WARNING, "Unable to create the secret - {0}",kce.getMessage());
        }
        LOGGER.log(Level.FINE, "Jenkins Secret created. - {0}", jenkinsSecret);
        return jenkinsSecret;
    }

    public static void updateSecretHelper(Credentials current, Credentials replacement) throws IOException
    {
        Map secretStringData = null;
        ObjectMeta metadata = new ObjectMeta();
        String ciName = System.getenv(KubeProviderConstants.JENKINS_URL).substring(System.getenv(KubeProviderConstants.JENKINS_URL).lastIndexOf("/")+1);
        String id = ((BaseStandardCredentials)replacement).getId();
        String secretName = "";
        String description = "";
        String credentialType = "";

        if(((BaseStandardCredentials)replacement).getDescription() != null){
            description = ((BaseStandardCredentials)replacement).getDescription();
        }
        metadata.setAnnotations(ImmutableMap.of(KubeProviderConstants.credentialDescription, description,
                                                KubeProviderConstants.credentialID, ((BaseStandardCredentials)replacement).getId()));
        ConfigBuilder cb = new ConfigBuilder();
        Config config = cb.build();
        DefaultKubernetesClient _client = new DefaultKubernetesClient(config);
        SecretList secretList = _client.secrets().withLabels(ImmutableMap.of(KubeProviderConstants.credentialID,id,KubeProviderConstants.ciName,ciName)).list();

        if(secretList != null  && secretList.getItems() != null && secretList.getItems().size()==1) {
            secretName = secretList.getItems().get(0).getMetadata().getName();
        }
        else {
            secretName = KubeCredentialNaming.generateName(((BaseStandardCredentials) replacement).getId(), ciName);
        }

        LOGGER.log(Level.FINE, "secret name to be updated - {0}",secretName);
        metadata.setName(secretName);

        if(current.getClass().getName().contains(KubeProviderConstants.FileCredentialsImplType)) {
            credentialType = KubeProviderConstants.FileCredentialsImplType;
            secretStringData = KubeProviderUtils.getSecretStringData(replacement);
        }
        else if(current.getClass().getName().contains(KubeProviderConstants.OpenShiftBearerTokenCredentialImplType)) {
            credentialType = KubeProviderConstants.OpenShiftBearerTokenCredentialImplType;
            secretStringData = KubeProviderUtils.getSecretStringDataOpenShiftUserPassword(replacement);
        }
        else if(current.getClass().getName().contains(KubeProviderConstants.OpenShiftTokenCredentialImplType)) {
            credentialType = KubeProviderConstants.OpenShiftTokenCredentialImplType;
            secretStringData = KubeProviderUtils.getSecretStringDataOpenShiftTokenCredentialImpl(replacement);
        }
        else if(current.getClass().getName().contains(KubeProviderConstants.DockerServerCredentialType))
        {
            credentialType = KubeProviderConstants.DockerServerCredentialType;
            secretStringData = KubeProviderUtils.getSecretStringDataDockerServerCredential(replacement);
        }
        else if(current.getClass().getName().contains(KubeProviderConstants.ServiceAccountCredentialType))
        {
            credentialType = KubeProviderConstants.ServiceAccountCredentialType;
            secretStringData = KubeProviderUtils.getSecretStringServiceAccountCredential(replacement);
        }
        else if(current.getClass().getName().contains(KubeProviderConstants.StringCredentialsImplType))
        {
            credentialType = KubeProviderConstants.StringCredentialsImplType;
            secretStringData = KubeProviderUtils.getSecretStringCredential(replacement);
        }
        else if(current.getClass().getName().contains(KubeProviderConstants.BasicSSHUserPrivateKeyImplType))
        {
            if(KubeProviderUtils.getPrivateKeySourceUtil(replacement).contains(KubeProviderConstants.DirectEntryPrivateKeySource))
            {
                credentialType = KubeProviderConstants.BasicSSHUserPrivateKeyImplType_DirectEntry;
                secretStringData = KubeProviderUtils.getSecretStringBasicUserPrivateKey(credentialType, replacement);

            }
            else if(KubeProviderUtils.getPrivateKeySourceUtil(replacement).contains(KubeProviderConstants.FileOnMasterPrivateKeySource))
            {
                credentialType = KubeProviderConstants.BasicSSHUserPrivateKeyImplType_FileEntry;
                secretStringData = KubeProviderUtils.getSecretStringBasicUserPrivateKey(credentialType, replacement);

            }
            else if(KubeProviderUtils.getPrivateKeySourceUtil(replacement).contains(KubeProviderConstants.UsersPrivateKeySource))
            {
                credentialType = KubeProviderConstants.BasicSSHUserPrivateKeyImplType_UserPrivateEntry;
                secretStringData = KubeProviderUtils.getSecretStringBasicUserPrivateKey(credentialType, replacement);

            }
        }
        else if(current instanceof CertificateCredentialsImpl)
        {
            if(((CertificateCredentialsImpl) replacement).getKeyStoreSource() instanceof CertificateCredentialsImpl.FileOnMasterKeyStoreSource) {
                credentialType = KubeProviderConstants.CertificateCredentialsImplType_FileKeyStore;
                secretStringData = ImmutableMap.of(KubeProviderConstants.CertificateCredentialsImpl_keyStoreFile, ((CertificateCredentialsImpl.FileOnMasterKeyStoreSource) ((CertificateCredentialsImpl) replacement).getKeyStoreSource()).getKeyStoreFile(),
                        KubeProviderConstants.CertificateCredentialsImpl_keyStorePassword, ((CertificateCredentialsImpl) replacement).getPassword().getPlainText());
            }
            else if(((CertificateCredentialsImpl) replacement).getKeyStoreSource() instanceof CertificateCredentialsImpl.UploadedKeyStoreSource)
            {
                credentialType = KubeProviderConstants.CertificateCredentialsImplType_UploadedKeyStore;
                secretStringData = ImmutableMap.of(KubeProviderConstants.CertificateCredentialsImpl_keyStoreBytes, Arrays.toString(((CertificateCredentialsImpl.UploadedKeyStoreSource) ((CertificateCredentialsImpl) replacement).getKeyStoreSource()).getKeyStoreBytes()),
                        KubeProviderConstants.CertificateCredentialsImpl_keyStorePassword, ((CertificateCredentialsImpl) replacement).getPassword().getPlainText());
            }
        }
        else if(current instanceof UsernamePasswordCredentialsImpl) {
            credentialType = KubeProviderConstants.UsernamePasswordCredentialsImplType;
            secretStringData = ImmutableMap.of(KubeProviderConstants.UsernamePasswordCredentialsImpl_userName, ((UsernamePasswordCredentialsImpl) replacement).getUsername(),
                    KubeProviderConstants.UsernamePasswordCredentialsImpl_password, ((UsernamePasswordCredentialsImpl) replacement).getPassword().getPlainText());
        }
        metadata.setLabels(ImmutableMap.of(KubeProviderConstants.credentialID,((BaseStandardCredentials)replacement).getId(),KubeProviderConstants.credentialType,credentialType,KubeProviderConstants.ciName,ciName));
        Secret kubeSecret = new SecretBuilder().withMetadata(metadata).withStringData(secretStringData).build();
        LOGGER.log(Level.FINE, "kube namespace", _client.getNamespace());
        Secret jenkinsSecret = _client.secrets().inNamespace("ciaas").createOrReplace(kubeSecret);
        LOGGER.log(Level.FINE, "Jenkins Secret updated.", jenkinsSecret);
    }





}
