package edu.stevens.cs594.crypto;

/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.Destroyable;

public final class PrivateCredential implements Destroyable {

    //X509 certificate chain
    private X509Certificate[] chain;

    //Private key
    private PrivateKey key;

    //Alias
    private String alias;

    public PrivateCredential(X509Certificate[] chain, PrivateKey key) {
        super();
        if (chain == null) {
            throw new IllegalArgumentException("Missing certificate for private credential.");
        }
        if (key == null) {
            throw new IllegalArgumentException("Missing private key for private credential."); 
        }
        this.chain = chain;
        this.key = key;
    }

    public PrivateCredential(X509Certificate[] chain, PrivateKey key, String alias) {
        this(chain, key);
        if (alias == null) {
            throw new IllegalArgumentException("Null alias for private credential.");
        }
        this.alias = alias;
    }

    public X509Certificate[] getCertificate() {
        return chain;
    }

    public PrivateKey getPrivateKey() {
        return key;
    }

    public String getAlias() {
        return alias;
    }

    public void destroy() {
        chain = null;
        key = null;
        alias = null;
    }

    public boolean isDestroyed() {
        return (chain == null && key == null && alias == null);
    }
}