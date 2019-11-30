/**
 * Copyright 2019 Quentin Castel.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package dev.openbanking4.spring.security.multiauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.openbanking4.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import javax.servlet.http.Cookie;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(AuthenticationApplication.class)
public class SecuredControllerWebMvcIntegrationTest {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper objectMapper;

    private String testPSD2Certificate =  "-----BEGIN CERTIFICATE-----\n" +
            "MIIFoDCCBIigAwIBAgIEWcWcQDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJH\n" +
            "QjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFBy\n" +
            "ZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMTkwODE5MTUzMTU2WhcNMjAwOTE5\n" +
            "MTYwMTU2WjBeMQswCQYDVQQGEwJHQjEWMBQGA1UEChMNVGVzdCBCYW5rIFBMQzEa\n" +
            "MBgGA1UEYRMRUFNER0ItVEVTVC0xMjM0NTYxGzAZBgNVBAMTEjAwMTU4MDAwMDFI\n" +
            "UVFycEFBSDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOPbgEZW7bLj\n" +
            "DzF2uJHpTwLk3lSX4updSyuR2Bp8XKIDgQcONWLa++U5n5vzarO/ZLr7f6f0dbnN\n" +
            "LI9CP3yFmUhjeDwE/d7VLD+vqygv3aDFDhshiCf956SmO4rNAMzUYMXIeSEmfuzi\n" +
            "USjL/bd80ftljrn2LSGnZqG/HamlLKdoYvnvtFlSHr2eUScu2rjmbEC+ZxQKQsSA\n" +
            "luoRfXi8/2QSXlqzapbCPrToFytDDbkoisv+r38Jc+rYuKQFScmb5XJdhHgIWzWa\n" +
            "ZMPPhsp6REw640GQgpiLk5rQbPj6zGAH4vGJUJmvu8oq4y6q/nPkpHxGDfUuDrIN\n" +
            "Rye+Vwm8gZcCAwEAAaOCAm8wggJrMA4GA1UdDwEB/wQEAwIHgDBpBggrBgEFBQcB\n" +
            "AwRdMFswEwYGBACORgEGMAkGBwQAjkYBBgMwRAYGBACBmCcCMDowEzARBgcEAIGY\n" +
            "JwEDDAZQU1BfQUkMG0ZpbmFuY2lhbCBDb25kdWN0IEF1dGhvcml0eQwGR0ItRkNB\n" +
            "MCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCB4AYDVR0gBIHYMIHV\n" +
            "MIHSBgsrBgEEAah1gQYBZDCBwjAqBggrBgEFBQcCARYeaHR0cDovL29iLnRydXN0\n" +
            "aXMuY29tL3BvbGljaWVzMIGTBggrBgEFBQcCAjCBhgyBg1VzZSBvZiB0aGlzIENl\n" +
            "cnRpZmljYXRlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIE9wZW5CYW5r\n" +
            "aW5nIFJvb3QgQ0EgQ2VydGlmaWNhdGlvbiBQb2xpY2llcyBhbmQgQ2VydGlmaWNh\n" +
            "dGUgUHJhY3RpY2UgU3RhdGVtZW50MG0GCCsGAQUFBwEBBGEwXzAmBggrBgEFBQcw\n" +
            "AYYaaHR0cDovL29iLnRydXN0aXMuY29tL29jc3AwNQYIKwYBBQUHMAKGKWh0dHA6\n" +
            "Ly9vYi50cnVzdGlzLmNvbS9vYl9wcF9pc3N1aW5nY2EuY3J0MDoGA1UdHwQzMDEw\n" +
            "L6AtoCuGKWh0dHA6Ly9vYi50cnVzdGlzLmNvbS9vYl9wcF9pc3N1aW5nY2EuY3Js\n" +
            "MB8GA1UdIwQYMBaAFFBzkcYhctN39P4AEgaBXHl5bj9QMB0GA1UdDgQWBBSApq4j\n" +
            "eB3V32VCf7m2n/dVkj6V2zANBgkqhkiG9w0BAQsFAAOCAQEAjSg6xnezKLzU7Svg\n" +
            "gMg9pDdcYQ5SZp7AMaepp2zm4q0JE166b9Rb/YCzrnjy+kDf1HheTsU5QiA+CeYI\n" +
            "ATFir6RXrAUy2opbf9vH8w9Ydqh7sfjhIdrMP4fqSdJ1OkQmPaVK9PZ3DXgtdPHu\n" +
            "Rdx5wL/dQlnETnV1rmnl2jdsXkq78e+ZggiY5a0U54AcDcrVIRGE7sRwFDRIqVYU\n" +
            "lOfaTSShkUvyR3J8O0/ZnFIaNa59Rn1jiPJwxc2NBnRWaAK7uYojui/dUa7Oj4IF\n" +
            "A5+aIsJQ0MAgofRQUweSbolFzjLhxjB87BYy0Lfxf300eN15LB5o/e3BIcIstP74\n" +
            "NUL7Aw==\n" +
            "-----END CERTIFICATE-----\n";

    @Test
    public void testSendingNoCredential() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("anonymous")
                .password("")
                .authorities(Collections.EMPTY_SET)
                .build();

        mvc.perform(get("/whoAmI").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }

    @Test
    public void testSendingACookie() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(new SimpleGrantedAuthority("admin"), new SimpleGrantedAuthority("clubFalafelKing")).collect(Collectors.toSet()))
                .build();

        mvc.perform(
                    get("/whoAmI")
                            .contentType(MediaType.APPLICATION_JSON)
                            .cookie(new Cookie("SSO", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbEtpbmciXX0.954F4BxnEPjeWeKlzQ_AFUwRvtT1fVg5qBjA4zOdMkQ"))
                )
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }


    @Test
    public void testAPIKey() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("bob")
                .password("")
                .authorities(Collections.EMPTY_SET)
                .build();

        mvc.perform(
                get("/whoAmI")
                        .contentType(MediaType.APPLICATION_JSON)
                        .param("key", "1NiIsInR5cCI6Ik")
        )
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }

    @Test
    public void testSendingACert() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("CN=0015800001HQQrpAAH, OID.2.5.4.97=PSDGB-TEST-123456, O=Test Bank PLC, C=GB")
                .password("")
                .authorities(Collections.EMPTY_SET)
                .build();

        mvc.perform(
                get("/whoAmI")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("x-cert", testPSD2Certificate)
        )
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }

    @Test
    public void testSendingAccessTokenAndCert() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("CN=0015800001HQQrpAAH, OID.2.5.4.97=PSDGB-TEST-123456, O=Test Bank PLC, C=GB")
                .password("")
                .authorities(Stream.of( new ScopeGrantType("accounts"), new ScopeGrantType("payments")).collect(Collectors.toSet()))
                .build();

        mvc.perform(
                get("/whoAmI")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("x-cert", testPSD2Certificate)
                        .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl19.NQSGWB3dA3NM7kGJF4DNzP6toEE_ljAbWfZ7S7d_WUk")
        )
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }
}
