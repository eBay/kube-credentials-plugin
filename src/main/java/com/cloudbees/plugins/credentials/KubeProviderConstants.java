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

public class KubeProviderConstants {

    /* Credential types */
    public static final String FileCredentialsImplType = "FileCredentialsImpl";

    public static final String OpenShiftBearerTokenCredentialImplType = "OpenShiftBearerTokenCredentialImpl";

    public static final String OpenShiftTokenCredentialImplType = "OpenShiftTokenCredentialImpl";

    public static final String UsernamePasswordCredentialsImplType = "UsernamePasswordCredentialsImpl";

    public static final String DockerServerCredentialType = "DockerServerCredentials";

    public static final String ServiceAccountCredentialType = "ServiceAccountCredential";

    public static final String StringCredentialsImplType = "StringCredentialsImpl";

    public static final String CertificateCredentialsImplType_UploadedKeyStore = "CertificateCredentialsImplUploadedKeyStore";

    public static final String CertificateCredentialsImplType_FileKeyStore = "CertificateCredentialsImplFileKeyStore";

    public static final String BasicSSHUserPrivateKeyImplType = "BasicSSHUserPrivateKey";

    public static final String BasicSSHUserPrivateKeyImplType_DirectEntry = "BasicSSHUserPrivateKeyDirectEntry";

    public static final String BasicSSHUserPrivateKeyImplType_FileEntry = "BasicSSHUserPrivateKeyFileEntry";

    public static final String BasicSSHUserPrivateKeyImplType_UserPrivateEntry = "BasicSSHUserPrivateKeyUserPrivateEntry";

    public static final String DirectEntryPrivateKeySource = "DirectEntryPrivateKeySource";

    public static final String FileOnMasterPrivateKeySource = "FileOnMasterPrivateKeySource";

    public static final String UsersPrivateKeySource = "UsersPrivateKeySource";



    /* Metadata keys */

    public static final String credentialType = "jenkins.io/credentials-type";

    public static final String ciName = "jenkins.io/ci-name";

    public static final String credentialDescription = "jenkins.io/credentials-description";

    public static final String credentialID = "jenkins.io/credential-id";


    /* Environment varibles */

    public static final String JENKINS_URL = "JENKINS_URL";

    /* Secret fields */

    //DockerServerCredentialType

    public static final String DockerServerCredentialType_clientKeySecret = "clientKeySecret";

    public static final String DockerServerCredentialType_clientCertSecret = "clientCertSecret";

    public static final String DockerServerCredentialType_serverCACertSecret = "serverCACertSecret";

    //FileCredentialsImplType

    public static final String FileCredentialsImplType_fileName = "fileName";

    public static final String FileCredentialsImplType_secretBytes = "secretBytes";

    //OpenShiftBearerTokenCredentialImpl

    public static final String OpenShiftBearerTokenCredentialImpl_userName = "username";

    public static final String OpenShiftBearerTokenCredentialImpl_password = "password";

    //OpenShiftTokenCredentialImpl
    public static final String OpenShiftTokenCredentialImplType_secret = "secret";

    //UsernamePasswordCredentialsImpl
    public static final String UsernamePasswordCredentialsImpl_userName = "username";
    public static final String UsernamePasswordCredentialsImpl_password = "password";

    //ServiceAccountCredential
    public static final String ServiceAccountCredential_id = "id";

    //StringCredentialsImpl
    public static final String StringCredentialsImpl_secretText = "secretText";

    //CertificateCredentialsImpl
    public static final String CertificateCredentialsImpl_keyStoreFile = "keyStoreFile";

    public static final String CertificateCredentialsImpl_keyStoreBytes = "keyStoreBytes";

    public static final String CertificateCredentialsImpl_keyStorePassword = "keyStorePassword";

    //BasicSSHPrivateKey
    public static final String BasicSSHPrivateKeyImpl_keyStoreFile = "sshFile";

    public static final String BasicSSHPrivateKeyImpl_passPhrase = "passPhrase";

    public static final String BasicSSHPrivateKeyImpl_user = "user";

    public static final String BasicSSHPrivateKeyImpl_privateKey = "privateKey";

    public static final String BasicSSHPrivateKeyImpl_numKeys = "numKeys";


}
