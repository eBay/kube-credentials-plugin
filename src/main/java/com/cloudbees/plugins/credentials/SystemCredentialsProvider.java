/*
 * The MIT License
 *
 * Copyright (c) 2011-2016, CloudBees, Inc., Stephen Connolly.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.cloudbees.plugins.credentials;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.converters.CredentialsConvertionException;
import com.cloudbees.plugins.credentials.converters.SecretToCredentialConverter;
import com.cloudbees.plugins.credentials.converters.SecretUtils;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.google.common.collect.ImmutableMap;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.BulkChange;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.XmlFile;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.*;
import hudson.model.listeners.SaveableListener;
import hudson.security.ACL;
import hudson.security.Permission;
import hudson.util.CopyOnWriteMap;
import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.api.model.SecretList;
import io.fabric8.kubernetes.client.*;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.export.ExportedBean;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.*;
import static com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL;
import static com.cloudbees.plugins.credentials.CredentialsScope.SYSTEM;


/**
 * The root store of credentials.
 */
@Extension
public class SystemCredentialsProvider extends AbstractDescribableImpl<SystemCredentialsProvider>
        implements Saveable {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(SystemCredentialsProvider.class.getName());

    /**
     * Old store of credentials
     *
     * @deprecated migrate to {@link #domainCredentialsMap}.
     */
    @Deprecated
    private transient List<Credentials> credentials = new CopyOnWriteArrayList<Credentials>();

    /**
     * Our credentials.
     *
     * @since 1.5
     */
    private Map<Domain, List<Credentials>> domainCredentialsMap = new CopyOnWriteMap.Hash<Domain, List<Credentials>>();

    /**
     * Our backing store.
     */
    private transient StoreImpl store = new StoreImpl();

    @CheckForNull
    private KubernetesClient client;
    @CheckForNull
    private Watch watch;

    /**
     * Constructor.
     */
    @SuppressWarnings("deprecation")
    public SystemCredentialsProvider() {
        List<Credentials> credList = new CopyOnWriteArrayList<Credentials>();
        IdCredentials cred = null;
        String ciName = null;
        try {
            LOGGER.log(Level.FINE, "Reading xml file for credentials details");
            XmlFile xml = getConfigFile();
            if (xml.exists()) {
                xml.unmarshal(this);
            }

            // Looping through the credentials.xml credentials and saving the XML credentials to Kube secrets
            domainCredentialsMap = DomainCredentials.migrateListToMap(domainCredentialsMap, credentials);

            if (domainCredentialsMap.containsKey(Domain.global())) {
                List<Credentials> list = domainCredentialsMap.get(Domain.global());

                if (list == null) {
                    LOGGER.log(Level.FINE, "No credentials on the domainCredentialsMap");
                } else {
                    LOGGER.log(Level.FINE, "Credentials list length from XML : {0} ",list.size());

                    for(Credentials credential : list){
                        LOGGER.log(Level.FINE, "XML credentials Name : : {0} ", ((BaseStandardCredentials)credential).getId());
                        Secret jenkinsCredentialSecret = KubeProvider.storeSecret(credential);
                        if(jenkinsCredentialSecret != null){
                            LOGGER.log(Level.FINE, "XML credential - {0} successfully added to Kubernetes cluster", ((BaseStandardCredentials) credential).getId());
                            try {
                                if (list.contains(credential)) {
                                    LOGGER.log(Level.FINE, "Attempting to delete Credential - {0} from XML", ((BaseStandardCredentials) credential).getId());
                                    removeCredentialsFromXML(Domain.global(),credential);
                                }
                            }catch(IOException ioe){
                                LOGGER.log(Level.FINE, "Deteing Credentials from XML resulted in an error - {0}", ioe.getMessage());
                            }
                        }
                        else{
                            LOGGER.log(Level.FINE, "Error in adding XML credential - {0} to Kubernetes cluster", ((BaseStandardCredentials) credential).getId());
                        }
                    }
                }
            }
            else{
                LOGGER.log(Level.FINE, "no global domain in domainCredentialsMap");
            }

            // Adding the secrets from kubernetes cluster to Jenkins Credentials
            ConfigBuilder cb = new ConfigBuilder();
            Config config = cb.build();
            DefaultKubernetesClient _client = new DefaultKubernetesClient(config);
            LOGGER.log(Level.FINER, "retrieving secrets from namespace - {0}",System.getenv("NAMESPACE"));
            ciName = System.getenv("JENKINS_URL").substring(System.getenv("JENKINS_URL").lastIndexOf("/")+1);
            SecretList jenkinsSecretList = _client.secrets().inNamespace(System.getenv("NAMESPACE")).withLabels(ImmutableMap.of("jenkins.io/ci-name",ciName)).list();
            LOGGER.log(Level.FINE, "Jenkins Secrets with labels - {0}", ciName);

            for (Secret jenkinsSecret : jenkinsSecretList.getItems()) {
                LOGGER.log(Level.FINE, "Secret Added - {0}", SecretUtils.getCredentialId(jenkinsSecret));
                cred = (convertSecret(jenkinsSecret));

                if (cred != null) {
                    LOGGER.log(Level.FINE, "secret found", cred);
                    credList.add(cred);

                    for (Credentials credential : credList) {
                        LOGGER.log(Level.FINE, "looping through the credentials", cred);
                        LOGGER.log(Level.FINE, "credential id", ((BaseStandardCredentials) credential).getId());
                    }
                }
                else
                {
                    LOGGER.log(Level.FINE, "looping through the credentials failed. null credential found");
                }

            }

            // adding Kube credentials to DomainCredentialsMap
            if (domainCredentialsMap.containsKey(Domain.global())) {
                List<Credentials> list = domainCredentialsMap.get(Domain.global());
                if (list == null) {
                    LOGGER.log(Level.FINE, "No credentials on the domainCredentialsMap");
                } else {
                    LOGGER.log(Level.FINE, "there are credentials on the domainCredentialsMap");
                    LOGGER.log(Level.FINE, "Credentials list length before : {0} ",list.size());

                    for(Credentials credential : credList) {
                        list.add(credential);
                    }
                    LOGGER.log(Level.FINE, "Credentials list length after : {0} ", list.size());
                }
            }
            else{
                LOGGER.log(Level.FINE, "no global domain in domainCredentialsMap");
            }
        }catch (KubernetesClientException kex) {
            LOGGER.log(Level.SEVERE, "Failed to initialise k8s secret provider, secrets from Kubernetes will not be available", kex);
            // TODO add an administrative warning to report this clearly to the admin
        }catch (IOException ioex) {
            LOGGER.log(Level.SEVERE, "Failed to read the kube credentials IO exception  on xml file read", ioex);
        }catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Failed to watch k8s secret , Exception", ex);
            // TODO add an administrative warning to report this clearly to the admin
        }

    }

    @CheckForNull
    IdCredentials convertSecret(Secret s) {
        String type = s.getMetadata().getLabels().get(SecretUtils.JENKINS_IO_CREDENTIALS_TYPE_LABEL);
        SecretToCredentialConverter lookup = SecretToCredentialConverter.lookup(type);
        LOGGER.log(Level.FINE, "Type found: {0}", type);
        if (lookup != null) {
            try {
                LOGGER.log(Level.FINE, "Found look up. Converting credentials found: {0}", type);
                return lookup.convert(s);
            } catch (CredentialsConvertionException ex) {
                LOGGER.log(Level.FINE, "Exception converting credential", ex);
                // do not spam the logs with the stacktrace...
                if (LOGGER.isLoggable(Level.FINE)) {
                    LOGGER.log(Level.FINE, "Failed to convert Secret '" + SecretUtils.getCredentialId(s) + "' of type " + type, ex);
                }
                else {
                    LOGGER.log(Level.WARNING, "Failed to convert Secret ''{0}'' of type {1} due to {2}", new Object[] {SecretUtils.getCredentialId(s), type, ex.getMessage()});
                }
                return null;
            }
        }
        else
        {
            LOGGER.log(Level.FINE, "Lookup is null");
        }

        LOGGER.log(Level.WARNING, "No SecretToCredentialConveror found to convert secrets of type {0}", type);
        return null;
    }
    
    /**
     * Ensure the credentials are loaded using SYSTEM during the startup and migration occurs as expected
     */
    @Initializer(after = InitMilestone.JOB_LOADED)
    public static void forceLoadDuringStartup() {
        getInstance();
    }
    
    /**
     * Gets the configuration file that this {@link CredentialsProvider} uses to store its credentials.
     *
     * @return the configuration file that this {@link CredentialsProvider} uses to store its credentials.
     */
    public static XmlFile getConfigFile() {
        // TODO switch to Jenkins.getInstance() once 2.0+ is the baseline
        return new XmlFile(Jenkins.XSTREAM2, new File(Jenkins.getActiveInstance().getRootDir(), "credentials.xml"));
    }

    /**
     * Gets the singleton instance.
     *
     * @return the singleton instance.
     */
    public static SystemCredentialsProvider getInstance() {
        return ExtensionList.lookup(SystemCredentialsProvider.class).get(SystemCredentialsProvider.class);
    }

    /**
     * Get all the ({@link Domain#global()}) credentials.
     *
     * @return all the ({@link Domain#global()}) credentials.
     */
    @SuppressWarnings("unused") // used by stapler
    public List<Credentials> getCredentials() {
        return domainCredentialsMap.get(Domain.global());
    }

    /**
     * Get all the credentials.
     *
     * @return all the credentials.
     * @since 1.5
     */
    @SuppressWarnings("unused") // used by stapler
    public List<DomainCredentials> getDomainCredentials() {
        return DomainCredentials.asList(getDomainCredentialsMap());
    }

    /**
     * Get all the credentials.
     *
     * @return all the credentials.
     * @since 1.5
     */
    @SuppressWarnings("deprecation")
    @NonNull
    public synchronized Map<Domain, List<Credentials>> getDomainCredentialsMap() {
        return domainCredentialsMap = DomainCredentials.migrateListToMap(domainCredentialsMap, credentials);
    }

    /**
     * Set all the credentials.
     *
     * @param domainCredentialsMap all the credentials.
     * @since 1.5
     */
    public synchronized void setDomainCredentialsMap(Map<Domain, List<Credentials>> domainCredentialsMap) {
        this.domainCredentialsMap = DomainCredentials.toCopyOnWriteMap(domainCredentialsMap);
    }

    /**
     * Short-cut method for {@link Jenkins#checkPermission(hudson.security.Permission)}
     *
     * @param p the permission to check.
     */
    private void checkPermission(Permission p) {
        // TODO switch to Jenkins.getInstance() once 2.0+ is the baseline
        Jenkins.getActiveInstance().checkPermission(p);
    }

    /**
     * Short-cut method that redundantly checks the specified permission (to catch any typos) and then escalates
     * authentication in order to save the {@link CredentialsStore}.
     *
     * @param p the permissions of the operation being performed.
     * @throws IOException if something goes wrong.
     */
    private void checkedSave(Permission p) throws IOException {
        checkPermission(p);
        Authentication old = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(ACL.SYSTEM);
        try {
            save();
        } finally {
            SecurityContextHolder.getContext().setAuthentication(old);
        }
    }

    /**
     * Implementation for {@link StoreImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized boolean addDomain(@NonNull Domain domain, List<Credentials> credentials) throws IOException {
        checkPermission(CredentialsProvider.MANAGE_DOMAINS);
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(domain)) {
            List<Credentials> list = domainCredentialsMap.get(domain);
            boolean modified = false;
            for (Credentials c : credentials) {
                if (list.contains(c)) {
                    continue;
                }
                list.add(c);
                modified = true;
            }
            if (modified) {
                checkedSave(CredentialsProvider.MANAGE_DOMAINS);
            }
            return modified;
        } else {
            domainCredentialsMap.put(domain, new ArrayList<Credentials>(credentials));
            checkedSave(CredentialsProvider.MANAGE_DOMAINS);
            return true;
        }
    }

    /**
     * Implementation for {@link StoreImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized boolean removeDomain(@NonNull Domain domain) throws IOException {
        checkPermission(CredentialsProvider.MANAGE_DOMAINS);
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(domain)) {
            domainCredentialsMap.remove(domain);
            checkedSave(CredentialsProvider.MANAGE_DOMAINS);
            return true;
        }
        return false;
    }

    /**
     * Implementation for {@link StoreImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized boolean updateDomain(@NonNull Domain current, @NonNull Domain replacement) throws IOException {
        checkPermission(CredentialsProvider.MANAGE_DOMAINS);
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(current)) {
            domainCredentialsMap.put(replacement, domainCredentialsMap.remove(current));
            checkedSave(CredentialsProvider.MANAGE_DOMAINS);
            return true;
        }
        return false;
    }



    /**
     * Implementation for {@link StoreImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized boolean addCredentials(@NonNull Domain domain, @NonNull Credentials credentials)
            throws IOException {
        checkPermission(CredentialsProvider.CREATE);
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(domain)) {
            List<Credentials> list = domainCredentialsMap.get(domain);
            if (list.contains(credentials)) {
                return false;
            }

            list.add(credentials);
            KubeProvider.storeSecret(credentials);
            //checkedSave(CredentialsProvider.CREATE);
            return true;
        }
        return false;
    }

    /**
     * Implementation for {@link StoreImpl} to delegate to while keeping the lock synchronization simple.
     */
    @NonNull
    private synchronized List<Credentials> getCredentials(@NonNull Domain domain) {
        // TODO switch to Jenkins.getInstance() once 2.0+ is the baseline
        if (Jenkins.getActiveInstance().hasPermission(CredentialsProvider.VIEW)) {
            List<Credentials> list = getDomainCredentialsMap().get(domain);
            if (list == null || list.isEmpty()) {
                return Collections.emptyList();
            }
            return Collections.unmodifiableList(new ArrayList<Credentials>(list));
        }
        return Collections.emptyList();
    }

    private void removeSecret(Credentials credentials)
    {
        String ciName = System.getenv(KubeProviderConstants.JENKINS_URL).substring(System.getenv(KubeProviderConstants.JENKINS_URL).lastIndexOf("/")+1);
        ObjectMeta metadata = new ObjectMeta();
        String secretName;
        Secret kubeSecret;
        ConfigBuilder cb = new ConfigBuilder();
        Config config = cb.build();
        DefaultKubernetesClient _client = new DefaultKubernetesClient(config);
        boolean deleted;
        SecretList secretList = _client.secrets().withLabels(ImmutableMap.of(KubeProviderConstants.credentialID,((BaseStandardCredentials)credentials).getId(),KubeProviderConstants.ciName,ciName)).list();
        if(secretList != null  && secretList.getItems() != null && secretList.getItems().size()==1) {
            secretName = secretList.getItems().get(0).getMetadata().getName();
        }
        else
        {
            secretName = KubeCredentialNaming.generateName(((BaseStandardCredentials) credentials).getId(), ciName);
        }
        LOGGER.log(Level.FINE, "secret name to be deleted : ",secretName);
        metadata.setName(secretName);
        kubeSecret = new SecretBuilder().withMetadata(metadata).build();
        deleted = _client.secrets().inNamespace(System.getenv("NAMESPACE")).delete(kubeSecret);
        if(deleted)
            LOGGER.log(Level.FINE, "Jenkins Secret deleted.");
        else
            LOGGER.log(Level.FINE, "Jenkins Secret was not deleted successfully. Secret Name - {0}",secretName);
    }

    /**
     * Implementation for {@link StoreImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials)
            throws IOException {
        checkPermission(CredentialsProvider.DELETE);
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(domain)) {
            List<Credentials> list = domainCredentialsMap.get(domain);
            if (!list.contains(credentials)) {
                return false;
            }
            list.remove(credentials);
            removeSecret(credentials);
            //checkedSave(CredentialsProvider.DELETE);
            return true;
        }
        return false;
    }

    private synchronized boolean removeCredentialsFromXML(@NonNull Domain domain, @NonNull Credentials credentials)
            throws IOException {
        checkPermission(CredentialsProvider.DELETE);
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(domain)) {
            List<Credentials> list = domainCredentialsMap.get(domain);
            if (!list.contains(credentials)) {
                return false;
            }
            list.remove(credentials);
            checkedSave(CredentialsProvider.DELETE);
            return true;
        }
        return false;
    }

    private void updateSecret(Credentials current, Credentials replacement) throws IOException
    {
        KubeProvider.updateSecretHelper(current, replacement);
    }


    /**
     * Implementation for {@link StoreImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized boolean updateCredentials(@NonNull Domain domain, @NonNull Credentials current,
                                                   @NonNull Credentials replacement) throws IOException {
        checkPermission(CredentialsProvider.UPDATE);
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(domain)) {
            List<Credentials> list = domainCredentialsMap.get(domain);
            int index = list.indexOf(current);
            if (index == -1) {
                return false;
            }
            list.set(index, replacement);
            updateSecret(current, replacement);
            //checkedSave(CredentialsProvider.UPDATE);
            return true;
        }
        return false;
    }

    /**
     * Implementation for {@link ProviderImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized StoreImpl getStore() {
        if (store == null) {
            store = new StoreImpl();
        }
        return store;
    }

    /**
     * {@inheritDoc}
     */
    public void save() throws IOException {
        checkPermission(Jenkins.ADMINISTER);
        if (BulkChange.contains(this)) {
            return;
        }
        XmlFile configFile = getConfigFile();
        configFile.write(this);
        SaveableListener.fireOnChange(this, configFile);
    }

    /**
     * Our management link descriptor.
     */
    @Extension
    @SuppressWarnings("unused") // used by Jenkins
    public static final class DescriptorImpl extends Descriptor<SystemCredentialsProvider> {
        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return "";
        }

    }

    @Extension
    @SuppressWarnings("unused") // used by Jenkins
    public static class ProviderImpl extends CredentialsProvider {

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.SystemCredentialsProvider_ProviderImpl_DisplayName();
        }

        /**
         * The scopes that are relevant to the store.
         */
        private static final Set<CredentialsScope> SCOPES =
                Collections.unmodifiableSet(new LinkedHashSet<CredentialsScope>(Arrays.asList(GLOBAL, SYSTEM)));

        /**
         * {@inheritDoc}
         */
        @Override
        public Set<CredentialsScope> getScopes(ModelObject object) {
            if (object instanceof Jenkins || object instanceof SystemCredentialsProvider) {
                return SCOPES;
            }
            return super.getScopes(object);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public CredentialsStore getStore(@CheckForNull ModelObject object) {
            if (object == Jenkins.getInstance()) {
                return SystemCredentialsProvider.getInstance().getStore();
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type,
                                                              @Nullable ItemGroup itemGroup,
                                                              @Nullable Authentication authentication) {
            return getCredentials(type, itemGroup, authentication, Collections.<DomainRequirement>emptyList());
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type, @Nullable ItemGroup itemGroup,
                                                              @Nullable Authentication authentication,
                                                              @NonNull List<DomainRequirement> domainRequirements) {
            if (ACL.SYSTEM.equals(authentication)) {
                CredentialsMatcher matcher = Jenkins.getInstance() == itemGroup ? always() : not(withScope(SYSTEM));
                return DomainCredentials.getCredentials(SystemCredentialsProvider.getInstance()
                        .getDomainCredentialsMap(), type, domainRequirements, matcher);
            }
            return new ArrayList<C>();
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type, @NonNull Item item,
                                                              @Nullable Authentication authentication) {
            return getCredentials(type, item, authentication, Collections.<DomainRequirement>emptyList());
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type, @NonNull Item item,
                                                              @Nullable Authentication authentication,
                                                              @NonNull List<DomainRequirement> domainRequirements) {
            if (ACL.SYSTEM.equals(authentication)) {
                return DomainCredentials.getCredentials(SystemCredentialsProvider.getInstance()
                        .getDomainCredentialsMap(), type, domainRequirements, not(withScope(SYSTEM)));
            }
            return new ArrayList<C>();
        }

        @Override
        public String getIconClassName() {
            return "icon-credentials-system-store";
        }
    }

    /**
     * Our {@link CredentialsStore}.
     */
    @ExportedBean
    public static class StoreImpl extends CredentialsStore {

        /**
         * Our store action.
         */
        private final UserFacingAction storeAction = new UserFacingAction();

        /**
         * Default constructor.
         */
        public StoreImpl() {
            super(ProviderImpl.class);
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public ModelObject getContext() {
            // TODO switch to Jenkins.getInstance() once 2.0+ is the baseline
            return Jenkins.getActiveInstance();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean hasPermission(@NonNull Authentication a, @NonNull Permission permission) {
            // we follow the permissions of Jenkins itself
            return getACL().hasPermission(a, permission);
        }

        public ACL getACL() {
            // TODO switch to Jenkins.getInstance() once 2.0+ is the baseline
            return Jenkins.getActiveInstance().getACL();
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        @Exported
        public List<Domain> getDomains() {
            return Collections.unmodifiableList(new ArrayList<Domain>(
                    SystemCredentialsProvider.getInstance().getDomainCredentialsMap().keySet()
            ));
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        @Exported
        public List<Credentials> getCredentials(@NonNull Domain domain) {
            return SystemCredentialsProvider.getInstance().getCredentials(domain);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean addDomain(@NonNull Domain domain, List<Credentials> credentials) throws IOException {
            return SystemCredentialsProvider.getInstance().addDomain(domain, credentials);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean removeDomain(@NonNull Domain domain) throws IOException {
            return SystemCredentialsProvider.getInstance().removeDomain(domain);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean updateDomain(@NonNull Domain current, @NonNull Domain replacement) throws IOException {
            return SystemCredentialsProvider.getInstance().updateDomain(current, replacement);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean addCredentials(@NonNull Domain domain, @NonNull Credentials credentials) throws IOException {
            return SystemCredentialsProvider.getInstance().addCredentials(domain, credentials);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials) throws IOException {
            return SystemCredentialsProvider.getInstance().removeCredentials(domain, credentials);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean updateCredentials(@NonNull Domain domain, @NonNull Credentials current,
                                         @NonNull Credentials replacement) throws IOException {
            return SystemCredentialsProvider.getInstance().updateCredentials(domain, current, replacement);
        }

        /**
         * {@inheritDoc}
         */
        @Nullable
        @Override
        public CredentialsStoreAction getStoreAction() {
            return storeAction;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void save() throws IOException {
            if (BulkChange.contains(this)) {
                return;
            }
            SystemCredentialsProvider.getInstance().save();
        }
    }

    /**
     * Expose the store.
     */
    @ExportedBean
    public static class UserFacingAction extends CredentialsStoreAction {

        /**
         * {@inheritDoc}
         */
        @NonNull
        public CredentialsStore getStore() {
            return SystemCredentialsProvider.getInstance().getStore();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getIconFileName() {
            return isVisible()
                    ? "/plugin/credentials/images/24x24/system-store.png"
                    : null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getIconClassName() {
            return isVisible()
                    ? "icon-credentials-system-store"
                    : null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.SystemCredentialsProvider_UserFacingAction_DisplayName();
        }
    }
}
