# Changelog

## [1.8.1](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.8.0...v1.8.1) (2026-04-08)


### Dependencies

* **deps-dev:** bump @typescript-eslint/eslint-plugin ([5e6086c](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/5e6086c9ad899bb6bc39eac8ca987a6fff5ddb33))
* **deps-dev:** bump com.diffplug.spotless:spotless-maven-plugin ([14b43b9](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/14b43b96e51accdd518dc35dd1868f9fa65ffd71))
* **deps-dev:** bump esbuild from 0.27.1 to 0.28.0 ([18db3f0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/18db3f0006b7b5be3b6b3c29620c4ef3d9bc937f))
* **deps-dev:** bump prettier from 3.2.5 to 3.8.1 ([#69](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/issues/69)) ([d5e68ff](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/d5e68ff28625b27687a975554c20d0c484542737))
* **deps:** bump com.nimbusds:nimbus-jose-jwt from 9.41.2 to 10.9 ([4a903d2](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/4a903d258e343d9de1167ad8d8ccaa0989ef7d78))
* **deps:** bump commons-validator:commons-validator ([4ee9e02](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/4ee9e026f213b5ab18804bcc761c45dba95ddebc))
* **deps:** bump org.projectlombok:lombok from 1.18.42 to 1.18.44 ([e19d342](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/e19d3425ea67ca8016cef3bb0f3387870d1a6317))
* **deps:** bump org.springframework.boot:spring-boot-starter-parent ([1e7602e](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/1e7602e554d232c9672bdcfc860cb0d185aa0ca6))

## [1.8.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.7.2...v1.8.0) (2026-04-01)


### Features

* add toggle to turn off sse for fcm pushes ([31df5ce](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/31df5ce98208ca12c2570a895a8da1342555ee61))

## [1.7.2](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.7.1...v1.7.2) (2026-03-11)


### Bug Fixes

* basepath for resources ([dd496a0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/dd496a0043cb207774d69fff775f7b90443286d8))

## [1.7.1](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.7.0...v1.7.1) (2026-03-10)


### Dependencies

* upgrade Spring Boot to 4.0.3 ([1e6b84c](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/1e6b84cc20132d5f00a03fae66966e5b2f332db0))

## [1.7.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.6.3...v1.7.0) (2026-03-04)


### Features

* **confirm:** add deny as an option ([6c420ad](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/6c420ad6ced9ee4b7a6a067abae2d59dde934857))
* **enroll:** align layout with call type ([f12d287](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/f12d2878ccbf9aad015abd8a112d31415ce6014e))


### Bug Fixes

* review cleanup ([f166539](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/f166539944a399a48bbe599a7b66559bba3bced3))

## [1.6.3](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.6.2...v1.6.3) (2026-02-19)


### Bug Fixes

* redirect to confirm page from push notification ([3d136f5](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/3d136f5bff78b3d98c2eaf61b33dd376ef8c3bbf))

## [1.6.2](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.6.1...v1.6.2) (2026-02-13)


### Bug Fixes

* add heartbeat to server sendevents ([#37](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/issues/37)) ([e7e1c1e](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/e7e1c1e01b187121696bb908260429dbb79723b8))
* flaky server send events test ([d006043](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/d006043dca2192121e8dacb0f56a934caaef8d05))

## [1.6.1](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.6.0...v1.6.1) (2026-02-12)


### Bug Fixes

* **challenge:** rm double encode url query param ([d5fe188](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/d5fe188a8a573c12a8cca37ceb4491dd4a2801a7))
* CODEOWNERS ([a297096](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/a297096fdaafda9efd095318ecf254fff7d5275e))

## [1.6.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.5.1...v1.6.0) (2026-02-11)


### Features

* **backend:** improve logging for spring controller ([b45fd30](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/b45fd30a475c0fd62d18aa1a9a1f49e9ecf77774))


### Bug Fixes

* **dpop:** RFC 9449 htu dpop fix ([c5057a9](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/c5057a9424371484541a5a52791699b2ff0f1b7a))
* lint & format ([fc355c0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/fc355c05319106a243e4f4c7909253ff6744f91d))
* remove compiler warnings ([60a2403](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/60a2403aec1148d9baa31760d192db54cf9f1bdf))

## [1.5.1](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.5.0...v1.5.1) (2026-02-10)


### Bug Fixes

* fcm message format ([fcba227](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/fcba22708e55c0206f4c896e78beb63c413d8e1e))

## [1.5.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.4.0...v1.5.0) (2026-02-03)


### Features

* adds proxy to RestTemplate if given ([cca6339](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/cca6339a0b1f248cf94085f33a0ff9bc8322f1aa))
* aligns proxy implementation and adds proxy example ([64c0d3e](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/64c0d3e7a95808572912b6f7926082952b1c4517))
* update README.md remove proxy ([59b97dc](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/59b97dc2f7b2044803e8635938d9cc84a4764db7))

## [1.4.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.3.0...v1.4.0) (2026-01-29)


### Features

* show firebase mock messages on ui ([f2dec1d](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/f2dec1da400ec35389c9c0e59de4d511775f3799))

## [1.3.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.2.0...v1.3.0) (2026-01-23)


### Documentation

* add readme for fcm mock ([#19](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/issues/19)) ([e23f1ef](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/e23f1ef99319c4838970af1cb7f078db29173a73))

## [1.2.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.1.0...v1.2.0) (2026-01-21)


### Features

* add loading key from filepath ([de20ad7](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/de20ad71ba9f3a4a0c6b7f348cfce2f361974a2c))
* read token in frontend and use iss to get url for iam ([e921697](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/e9216977070bfe5a19d29430187739f5d69310fe))

## [1.1.0](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/compare/v1.0.0...v1.1.0) (2026-01-19)

### Features

- initial complete version with required configuation ([edeba6e](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/edeba6e2f12b115b95af6b67e80ba09915686333))

## 1.0.0 (2026-01-13)

### Features

- **ci:** add github-build ([b873942](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator/commit/b873942345ab7c5f6507d0123c421fa9ff24bf39))
