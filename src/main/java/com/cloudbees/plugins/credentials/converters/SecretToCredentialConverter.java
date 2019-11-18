/*
 * The MIT License
 *
 * Copyright 2018 CloudBees, Inc.
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
package com.cloudbees.plugins.credentials.converters;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import io.fabric8.kubernetes.api.model.Secret;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class that converts a secret of a given type to an {@link IdCredentials}.
 */
public abstract class SecretToCredentialConverter implements ExtensionPoint {

    private static final Logger LOGGER = Logger.getLogger(SecretToCredentialConverter.class.getName());

    /**
     * Check if this converter can transform secrets of a given type.
     *
     * @param type the type of secret.  This is <em>normally</em> the symbol attached to the credential type by the credential binding plugin.
     * @return {@code true} iff this {@code SecretToCredentialConvertor} can convert secrets of the specified type.
     */
    public abstract boolean canConvert(String type);

    /**
     * Convert the given {@code Secret} to an {@code IdCredential}.
     * This will only be called for a secret of a type that the class has previously returned {@code true} from {@link #canConvert(String)}.
     *
     * @param secret the Secret to convert.
     * @return the IdCredentials created from the secret.
     * @throws CredentialsConvertionException if the Secret could not be converted.
     */
    public abstract IdCredentials convert(Secret secret) throws CredentialsConvertionException;

    /**
     * Helper to obtain all the implementations of this {@code ExtensionPoint}
     *
     * @return the ExtensionList containing all of the implementations.
     */
    public static final ExtensionList<SecretToCredentialConverter> all() {
        return ExtensionList.lookup(SecretToCredentialConverter.class);
    }

    /**
     * Helper to obtain the SecretToCredentialConvertor that can convert this type of secret.
     *
     * @param type the type of the secret to convert.
     * @return the SecretToCredentialConvertor to use for converting the secret.
     */
    @CheckForNull
    public static final SecretToCredentialConverter lookup(String type) {
        ExtensionList<SecretToCredentialConverter> all = all();
        for (SecretToCredentialConverter stcc : all) {
            LOGGER.log(Level.FINE, "Credential convertor type : "+ stcc.getClass() +" : "+ stcc.toString() + " to jenkins credentials");
            if (stcc.canConvert(type)) {
                LOGGER.log(Level.FINE, "able to convert type : "+ type + " to jenkins credentials");
                return stcc;
            }
            else{
                LOGGER.log(Level.FINE, "cannot convert type : "+ type + " to jenkins credentials");
            }
        }
        return null;
    }
}