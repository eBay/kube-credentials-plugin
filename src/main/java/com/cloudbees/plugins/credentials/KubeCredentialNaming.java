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

public class KubeCredentialNaming {

    private static String PREFIX_CREDENTIAL = "sec";
    private static String DELIMITER = "-";

    public static String generateName(String id, String ciName)
    {
        return (PREFIX_CREDENTIAL + DELIMITER + id + DELIMITER + ciName).toLowerCase();
    }

}
