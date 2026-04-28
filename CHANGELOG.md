# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## 0.4.0 (2026-04-28)


### ⚠ BREAKING CHANGES

* the existing -p/--port option now applies only to the HTTP server
existing users requiring a custom HTTPS port must now use -s/--tls-port
* hardcoded usages of the previous endpoint (`/endsession`)
must be updated to `/oidc/logout`

### Features

* add options to save and load JWK files ([2313fed](https://github.com/bluecatengineering/mock-oidc-provider/commit/2313fed4b7d712d04b9073523b9345f282719db7))
* allow both http and https servers to run simultaneously ([e39ab7a](https://github.com/bluecatengineering/mock-oidc-provider/commit/e39ab7a8be1051712ea1d0246e27b854ad7f7579))
* allow defining client claims for the client credentials flow ([083e049](https://github.com/bluecatengineering/mock-oidc-provider/commit/083e049032753104f6cfa81f4f4f6b5e8897c899))
* allow overriding issuer_url with a static value from environment variable ([45042b1](https://github.com/bluecatengineering/mock-oidc-provider/commit/45042b17a38e77c80defafd11229cc51edc5b069))
* allow overriding issuer_url with a static value from environment variable ([700e4a2](https://github.com/bluecatengineering/mock-oidc-provider/commit/700e4a22d35d32d7363138088699bc772345f4f9))
* change the end session endpoint ([1649370](https://github.com/bluecatengineering/mock-oidc-provider/commit/16493703e127c6e2983697412f2119b48048307a))
* initial commit ([1b39fd5](https://github.com/bluecatengineering/mock-oidc-provider/commit/1b39fd52b067e8eda2462c5a9655ae6d1b51d9c5))


### Bug Fixes

* ensure the client audience is included in the token ([222f5d5](https://github.com/bluecatengineering/mock-oidc-provider/commit/222f5d5fbd9f357f60abd73b167ae383d59c5788))
* fix issues found in code review ([702dd2a](https://github.com/bluecatengineering/mock-oidc-provider/commit/702dd2afd1daf3d3ae711ff44a99e2580570ecf7))
* use process.env instead of undefined env variable in getIssuer ([99bf0bc](https://github.com/bluecatengineering/mock-oidc-provider/commit/99bf0bc22abe6e26e94cd74411dda581ed89ddd4))

## [0.3.4](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.3...v0.3.4) (2026-04-01)

### Bug Fixes

- ensure the client audience is included in the token ([222f5d5](https://github.com/bluecatengineering/mock-oidc-provider/commit/222f5d5fbd9f357f60abd73b167ae383d59c5788))

## [0.3.3](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.2...v0.3.3) (2026-03-30)

## [0.3.2](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.1...v0.3.2) (2026-03-30)

## [0.3.1](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.0...v0.3.1) (2026-03-30)

### Features

- allow defining client claims for the client credentials flow ([083e049](https://github.com/bluecatengineering/mock-oidc-provider/commit/083e049032753104f6cfa81f4f4f6b5e8897c899))

## [0.3.0](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.2.0...v0.3.0) (2025-12-05)

### ⚠ BREAKING CHANGES

- the existing -p/--port option now applies only to the HTTP server
  existing users requiring a custom HTTPS port must now use -s/--tls-port

### Features

- allow both http and https servers to run simultaneously ([e39ab7a](https://github.com/bluecatengineering/mock-oidc-provider/commit/e39ab7a8be1051712ea1d0246e27b854ad7f7579))

## [0.2.0](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.1.1...v0.2.0) (2025-12-05)

### ⚠ BREAKING CHANGES

- hardcoded usages of the previous endpoint (`/endsession`)
  must be updated to `/oidc/logout`

### Features

- add options to save and load JWK files ([2313fed](https://github.com/bluecatengineering/mock-oidc-provider/commit/2313fed4b7d712d04b9073523b9345f282719db7))
- change the end session endpoint ([1649370](https://github.com/bluecatengineering/mock-oidc-provider/commit/16493703e127c6e2983697412f2119b48048307a))

## [0.1.1](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.1.0...v0.1.1) (2025-07-07)

### Bug Fixes

- fix issues found in code review ([702dd2a](https://github.com/bluecatengineering/mock-oidc-provider/commit/702dd2afd1daf3d3ae711ff44a99e2580570ecf7))
