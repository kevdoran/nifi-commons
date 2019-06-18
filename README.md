# NiFi Commons

A collection of libraries for NiFi projects.

Currently, just security-related libraries, but in the future this could hold other shared code as well. For now, see the [NiFi Commons Security README](nifi-commons-security/README.md).

## To Do List

NiFi Commons Security:

- [x] Identity Provider Interface
- [x] Identity Mapper Interface
- [x] Login Redirect Provider Interface
- [ ] Identity Mapper Transform functions
- [x] X509 Identity Provider (TLS mutual auth client cert identity)
- [x] LDAP Identity Provider (for user/pass login)
- [x] Trusted Proxy Identity Provider (for reverse-proxy passed identity)
- [x] Knox SSO Identity Provider (for authenticating KnoxSSO tokens)
- [x] Kerberos SPNEGO Identity Provider (for authenticating Kerberos tickets)
- [ ] Kerberos Identity Provider (for Kerberos user/pass login)
- [ ] OIDC Identity Provider
- [ ] OAuth2 Identity Provider 
- [ ] JWT Management (service/library, Identity Provider)
- [ ] HTTP signed messages (library, Identity Provider)
- [x] Bridge classes for Spring Security interoperability
- [x] Mechanism for configurable Identity Provider Filter order
- [x] Spring Boot starter assembly
