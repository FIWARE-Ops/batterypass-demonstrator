# Access services using the traditional i4Trust-flow

The demonstrator supports data-access via [iShares OAuth 2.0 / OpenID Connect 1.0](https://dev.ishare.eu/introduction/standards.html) as defined in the latest release of the [i4Trust-Buildingblocks](https://github.com/i4Trust/building-blocks).

## Setup 

To use the flow in a batterypass data-space, the following roles have to be provided:

- TrustAnchor - the [iShare Scheme-Owner Endpoint](https://dev.ishare.eu/scheme-owner/parties-id.html) for verifying trusted participants
- Delegation Endpoint - an implementation of [iShare Delegation Endpoint](https://dev.ishare.eu/delegation/endpoint.html) for providing access to iShare policies
- (optional) Token Endpoint - the [iShare Token Endpoint](https://dev.ishare.eu/common/token.html) to provide M2M-Tokens in the M2M usecase
- (optional) Identity Provider - the [iShare Identity Provider Endpoint](https://dev.ishare.eu/identity-provider/authorize.html) to provide H2M tokens for the H2M usecase
- Policy Decision Point/Policy Enforcement Point - validates and evaluates the policies in the token and enforces the decision on the request

### Trust Anchor

To assert trust between all participants in the data-space, a central Trust Anchor is used. It implements [the Parties](https://dev.ishare.eu/scheme-owner/parties.html) and [the Trusted List](https://dev.ishare.eu/scheme-owner/trusted-list.html) Endpoint. To simplify the demonstrational environment, the [FIWARE iShare Satellite](https://github.com/FIWARE/ishare-satellite) is deployed and preconfigured with the participant ONE, TWO and THREEs certificates.
The satellite identifies itself with the id ```EU.EORI.DEBATTERYPASSSAT```.
All certificates and keys used can be found in the [certificates-folder](../certificates/). They are specifically created for this test environment and therefore can be shared publicly.

### Delegation Endpoint

The actual authorization happens through the [iShare Delegation flows](https://dev.ishare.eu/delegation/endpoint.html). In the environment, [Keyrock](https://github.com/ging/fiware-idm) is used to provide that capability. To allow access via the M2M-flow, a policy has to be created(the following example allows participant TWO to request Batteries at participant ONE):

> :bulb: See [Access Token Doc](../README.md#policyregistry-access-token) for authorization

```shell
# Policy creation endpoint on the keyrock of ONE
curl --location --request POST 'https://idm-one.batterypass.fiware.dev/ar/policy' \
# Token retrieved, following the steps in the hint
--header 'Authorization: Bearer <TOKEN>' \
--header 'Content-Type: application/json' \
--data-raw '{
	"delegationEvidence": {
		"notBefore": 1614354348,
		"notOnOrAfter": 1737894651,
        // iShare identifier of ONE
		"policyIssuer": "EU.EORI.DEONE",
		"target": {
            // iShare identifier of TWO
			"accessSubject": "EU.EORI.DETWO"
		},
		"policySets": [
			{   
                "target": {
                    "environment": {
                        "licenses": [ "ISHARE.0001" ]
                    }  
                },
				"policies": [
					{
						"target": {
							"resource": {
                                // resource definition: all identifieres and attributes for entity-type BATTERY
								"type": "BATTERY",
								"identifiers": [
									"*"
								],
								"attributes": [
									"*"
								]
							}https://github.com/i4Trust/tutorials/tree/main/PacketDelivery-ReferenceExample/Data-Service-Consumer#user-policies
						},
						"rules": [
							{
								"effect": "Permit"
							}
						]
					}
				]
			}
		]
	}
}'
```

> :bulb: If the H2M flow should be used, another policy targeting the user in the Keyrock of TWO has to be provided. See [the i4Trust-Tutorials](https://github.com/i4Trust/tutorials/tree/main/PacketDelivery-ReferenceExample/Data-Service-Consumer#user-policies) for more information.

### Token Endpoint / Identity Provider

[Keyrock](https://github.com/ging/fiware-idm) also provides those two roles. In the M2M-Flow, a token can be retrieved in 2. Steps:

1. Generate an [iShare-Token](https://dev.ishare.eu/introduction/jwt.html) for participant TWO, targeting participant ONE - see [utils-section "iShare-JWT"](../README.md#ishare-jwt)
2. exchange the token with an Access Token at the Keyrock of ONE:
```shell
curl --location --request POST 'https://idm-one.batterypass.fiware.dev/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
--data-urlencode 'scope=iSHARE' \
--data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
--data-urlencode 'client_assertion=<TOKEN>' \
--data-urlencode 'client_id=EU.EORI.DETWO'
```

> :bulb: If the H2M flow should be used, a user-token has to be retrieved from the Keyrock TWO. See the information about [Data Service Consumers](https://github.com/i4Trust/tutorials/tree/main/PacketDelivery-ReferenceExample/Data-Service-Consumer#data-service-consumer) in the i4Trust tutorials.

### Policy Decision Point/Policy Enforcement Point

To enforce authorization on requests in an [i4Trust-compliant way](https://github.com/i4Trust), a Policy Decision Point(PDP) and a Policy Enforcement Point(PEP) is required. We provide this with the [FIWARE Kong Plugin for NGSI-iShare Policies](https://github.com/FIWARE/kong-plugins-fiware). The PEP is configured to intercept all requests to the ```/i4trust``` sub-path.

Verification is done in the following steps:

1. Validate the JWT's signature
2. Validate that the JWT is signed by a trusted participant, using the [Trusted-List endpoint](https://dev.ishare.eu/scheme-owner/trusted-list.html) from the [satellite](#trust-anchor).
3. Request and evaluate the required policy from the [Policy Registry](#delegation-endpoint)

The plugin then enforces the decision on the request.
