# Access services using VerifiableCredentials

The demonstrator supports the data-access via [SIOP-2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) using [VerfiableCredentials](https://www.w3.org/TR/vc-data-model/) as defined in the latest release of the [i4Trust-Buildingblocks](https://github.com/i4Trust/building-blocks).

## Setup

To use this in the batterypass data-space, the following roles have to be provided:

- Credentials Issuer - issue the actual VerifiableCredentials to users
- Credentials Verifier/RelyingParty - verify a credential and exchange it with JWT-token
- Policy Decision Point - checks the contents of the credential provided via JWT and authorizes or rejects the request
- Policy Registry - holds the information about trusted issuers and policies assigned to roles

The components fullfilling those roles:

### Credentials Issuer

As Issuer, every participant has an instance of [Keycloak](https://www.keycloak.org/) with the [Keycloak-VC-Issuer Plugin](https://github.com/wistefan/keycloak-vc-issuer) installed. They are available at ```kc-<ONE|TWO|THREE>.batterypass.fiware.dev```. Each of them has various users preconfigured, that can retrieve credentials for accessing participant ONE at ```https://one.batterypass.fiware.dev/vc/ngsi-ld/v1```.

> :bulb: for simplicity, all users have there username as there password.

Get VC for users in ONE:
- go to https://kc-one.batterypass.fiware.dev/realms/fiware-server/account/ and login with user admin-user
- go to the verifiable credentials tab
- choose "BatteryPassAuthCredential" and "Generate VerifiableCredential Request"
- use a wallet like ```wallet.fiware.dev``` and scan the credential
