# Apache Shiro JWT integration

This project demonstrates integration of Apache Shiro, JWT and JAX-RS for authorization.

We define a Shiro JwtFilter for extracting JWT bearer tokens from the HTTP Authentication header. The JWT filter
disables caching. In shiro.ini we disable the rememberMe function.

The JwtRealm authenticates principals by validating the JWT token (note that the real authentication took place
before obtaining the token). Principals are authorized by extracting roles from the token, and looking up permissions
associated with the role in roles.ini (same syntax as shiro.ini).

Permissions are exposed for usage in the front-end by a permissions endpoint. This endpoint returns all
permissions associated with the roles in the JWT token.

TODO/wishlist:
- Angular demo. Plan: use NPM shiro-trie, define directives for checking.
- JEE8/MicroProfile integration
- Quarkus integration (Vert.x, without servlet)