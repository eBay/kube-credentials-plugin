# Summary of Project
This is a Jenkins plug-in project that works with Kubernetes Secrets.  This project includes some code from other projects: 
1. A Jenkins Credential plugin, available at: (http://wiki.jenkins-ci.org/display/JENKINS/Credentials+Plugin); and 
2. A Kubernetes plug-in, available at: https://github.com/jenkinsci/kubernetes-credentials-provider-plugin.

This plug-in will be useful if your organization uses Jenkins and uses Kubernetes, and wishes to read/store credentials in a secure way. Specifically, the Jenkins Credential sample above stores credentials on the local disk within an encrypted local text file. kubernetes-credentials-provider-plugin gets secrets from Kubernetes Secrets, but it does not store secrets.  The kubernetes-credentials-provider-plugin also supports a limited number of credential types. This project, however, stores many kinds of credentials into Kubernetes Secrets. This project is intended to have more features than the samples above.

## Prerequisites

This plug-in requires Kubernetes and Jenkins to be setup and running. Specifically, the Jenkins instance must be running in a Kubernetes cluster.  The user must configure a namespace where secrets are to be stored. A namespace is created in Kubernetes, and then that namespace is placed in a Jenkins environment variable ("NAMESPACE" environment variable). This plug-in will use this variable.

## Documentation

The installation, configuration and usability of a Jenkins plugin is well documented here:
https://github.com/jenkinsci/credentials-plugin/tree/master/docs

This plug-in is installed, configured, and used in the same way.

## How to install

Run

	mvn clean package

to create the plugin .hpi file.

To install:

1. Copy the resulting ./target/credentials.hpi file to the $JENKINS_HOME/plugins directory. Don't forget to restart Jenkins afterwards.

2. Use the plugin management console (http://example.com:8080/pluginManager/advanced) to upload the hpi file. You have to restart Jenkins in order to find the pluing in the installed plugins list.

## Testing

For testing, please follow the process below.
1. Upload the plugin to the Jenkins instance running on kubernetes and check the end-to-end flow with respect to credentials.
2. When you make any changes to the code, one of the scenarios to test is validating that the credentials/secrets persist even after a restart of the Jenkins instance.

## Remaining To Do Items

- Some tests are already included in this repo, but there is more work to be done to increase code coverage. Contributions would be very welcome.
- Enablement of a custom domain feature separate from the default domain.

## License
Copyright 2019 eBay Inc. <BR>
Author/Developer: Vasumathy Seenuvasan, Ravi Bukka, Murali Thirunagari <BR>

Use of this source code is governed by an MIT-style license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

## Notice of 3rd Party Code Use

This project includes or modifies code from the open source project(s) listed in a NOTICE.md.
