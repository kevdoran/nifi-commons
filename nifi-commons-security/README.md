# NiFi Commons Security

This document explains the design goals, implementation, and usage of the NiFi Commons Security library.

## Table of Contents
  
- [Goals](#goals)  
    - [Specific Objectives](#specific-objectives)
- [Design](#design)
    - [Authentication](#authentication)
    - [Authorization](#authorization)
- [Implementation](#implementation)
- [Usage](#usage)

## Goals

The high-level goals of the NiFi Commons Security library are:

- Provide a secure model for authentication (verifying identity credentials) and authorization (access control of user to application resources and actions).
- Ease of use to configure, both manually by an admin or automated by a managed deployment process. Secure by default, hard to configure insecurely.
- Flexible enough to work for a variety of deployment approaches (on-prem, cloud, container, k8s, standalone/multi-node, proxied), with little or no modification.
- Flexible enough to integrate with popular Enterprise security systems/approaches (such as authn and authz) out of the box.
- Extensible enough to allow for user customization to integrate with systems beyond what is included out of the box in a standard build.
- Reusable across projects in the NiFi ecosystem (NiFi, MiNiFi Java, Registry, and other future services).
- Maintainable design and implementation.

### Specific Objectives

- Standardize the provider implementations on a single, unified interface. 
  Today, in NiFI we have several one-off implementations of authentication/identity providers for x509, jwt, kerberos, oidc, ldap, etc. 
  This presents challenges for code maintainability and limits sys admin configurability as so much is hard-coded into our authentication mechanisms today.
- Provide an authorization model that works well with both Apache Sentry and Apache Ranger
- Provide straight-forward configurability for running securely behind all the popular reverse proxies (Knox, Nginx, Apache HTTPd, HAProxy, Traefik, etc.), both single/multi-hop.
- SSO tokens from external SSO providers (OIDC for example) should be 
- Admins should be able to configure per-resource authorization rules, but they should not be required to. 

## Design

The design for the NiFi Commons Security library are based on: 
 - This design iterates on the AuthN/AuthZ model used today in NiFi, NiFi Registry. This design aims to maintain the same basic principles while addressing specific difficulties admins/users/developers encounter today.
 - This design is informed by research into a number of modern web applications as well as example usage of popular security frameworks such as Spring Security.

### Authentication

- Authentication / Identity determination will be handled by request filters. 
    - We will offer some API as a standard for how to write/configure Authentication providers that third-parties can use to implement their own providers.
    - Multiple, ordered filters will be configurable, so for example we can support certificate-based, mutual TLS (for services) _and_ LDAP authentication (for UI users) simultaneously.
    - The filter can either _do_ authentication (e.g., extract and verify credentials for an identity claim), or, alternatively, it can just be configured to extract user/principal from a trusted authenticating proxy that is handling auth and sending the user identity and attributes in the request (e.g., something like a X-WebAuth-User header or a Knox SSO token)
- UI users and other servers/services should be able to authenticate using different authentication providers. 
    - One way to do this is to keep REST APIs paths for services distinguishable from REST APIs paths for the UI. 
      They can start controller/resource implementations, but use Request Filters to create aliases (/service/* and /user/*) that route more than one path to the same implementation.
    - This allows different security filter chains to be configured for each REST API path prefix, and also allows reverse proxies handling authentication to be configured with multiple backends with different authentication rules,
      e.g., /service/* secured by mutual TLS with NEED client cert so that the proxy re-negotiates TLS connections, and UI users accessing /user/* secured by basic auth that prompts for user/pass credentials.
- Interoperability with other security frameworks, such as Spring Security, would be a nice to have so that we can leverage other authenticating request filter implementations in our out-of-the-box providers.  

### Authorization

- Endpoints will be protected by _Permissions_.
    - Permissions will be abstractions of actions and resources. 
    - Example Permissions include things like: 
        - CRUD abstractions: "create Xs", "view Ys", "modify Zs", etc.
        - Higher level abstractions: "Developer access", "Service access", "Full Read-only access", "Admin access"
    - Permissions will be customizable by mapping a permission label (e.g. "view widgets") to REST API methods (e.g., `GET /widgets/*`, `GET /widget-details/*`).
    - Permissions as an abstraction on top of raw REST API resource paths allow us to provide both:
        - coarse/simple configuration that comes out of the box (e.g., the typical user just needs to deal with a few high level resource concepts) in which we supply reasonable interpretations of which API endpoints/resources are accessible for a smaller set of understandable permissions.
        - fine-grained/complex configuration via user-defined permissions as mappings of Permissions labels to a collection of REST API endpoints or CRUD operations.
- Access Control will be Role Based (RBAC) or Attribute Based (ABAC), in which admin configured _Policies_ map user roles/attributes to Permissions.
    - Example Policies:
        - Users with role "admin" have "full access" permission
        - Users in group "app-users" have "view ui" permission
        - Users with attribute "app-role=author" have "author widgets" permission
        - Users with attribute "app-role=operator" have "deploy widgets" permission
- Users will not need to exist in order to define authorization policies. Authorization policies can be set against any attribute of the user, including as identity/name, group, role, or combination of other key/value attributes. 
    - This is key for flexible integration with external SSO / user directories as well as programmatic provisioning in which the expectation is new users/services will authenticate regularly and need to be already mapped into an existing policy.
    - Authentication Filter will be responsible for supplying the application with the user identity *and* role/attributes. We will provide filters that do this for common usage scenarios.
    - The first time a new user is authenticated, a user object may be created/persisted/cached by the application, but that data must be updated by the application if the AuthenticationFilter detects changes on future requests (e.g., a new role).
- We will define an internal API that the application invokes to authorize a User object (including the user metadata/role/attributes) against policies for permission to perform an action. 
    - This API will be extensible so that if can be backed by external/centralized policy managers such as Ranger or Sentry.

## Implementation

### Security API Interfaces

The following interfaces are extension points that third-party providers can implement in order to extend the core framework: 

- Identity Provider - Responsible for extracting credentials from HTTP requests, authenticating them, and providing the request context with user identity and details. 
- Identity Mapper - Responsible for transforming the resulting identity output from an identity mapper into a final identity in the request context. For example, a certificate DN to a user name.
- Login Redirect Provider - Responsible for redirecting unauthenticated requests to an external SSO login page.

### Included Identity Providers 

Note, some of these are planned but not yet implemented.

- X509 Identity Provider (TLS mutual auth client cert identity)
- LDAP Identity Provider (for user/pass login)
- Trusted Proxy Identity Provider (for reverse-proxy passed identity)
    - Proxy trust mechanisms:
        - HTTP signed messages (issued symetric keys): https://youtu.be/9CJ_BAeOmW0?t=2336
        - Proxy client certificate
        - Proxy IP whitelist
        - None (assume using Itsio or something to secure Proxy<->Service communication)
- Knox SSO Identity Provider (for authenticating KnoxSSO tokens)
- Kerberos SPNEGO Identity Provider (for authenticating Kerberos tickets)
- Kerberos Identity Provider (for Kerberos user/pass login)
- OIDC Identity Provider
- OAuth2 Identity Provider 
- Signed HTTP Message Identity Provider
    
 
## Resources for Further Reading

- Spring Security Architecture: https://spring.io/guides/topicals/spring-security-architecture/
- Digitally signed messages with symmetric keys or public/private keys, similar to HTTP signing
    - https://tools.ietf.org/html/draft-cavage-http-signatures-10
    - https://youtu.be/9CJ_BAeOmW0?t=2336
- Authorization Models: https://dinolai.com/notes/others/authorization-models-acl-dac-mac-rbac-abac.html

## Usage

TODO: In the future, this section will include usage instructions and examples for the library. For now, see the code examples in [nifi-commons-examples](../nifi-commons-examples).
