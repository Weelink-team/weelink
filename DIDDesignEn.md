# OneITFarm DID Method Specifications
## 1. DID-Auth-Protocol
This article defines the specifications of OneITFarm DID-Auth-Protocol in detail for users' reference.

## 2. Table of Contents
- [DID-Auth-Protocol](#1-did-auth-protocol)
- [Table of Contents](#2-table-of-contents)
- [Abstract](#3-abstract)
- [Motivation](#4-motivation)
- [DID](#5-did)
  - [Create DID](#51-create-did)
  - [Declare DID](#52-declare-did)
  - [Read DID](/#53-read-did)
  - [Update DID](#54-update-did)
  - [Revoke DID](#55-revoke-did)
- [DID Document](#6-did-document-diddoc)
  - [Create DID Document](##61-create-did-document)
  - [Declare DID Document](##62-declare-did-document)
  - [Read DID Document](##63-read-did-document)
  - [Update DID Document](##64-update-did-document)
- [Workflow](#7-workflow)
  - [Pre-knowledge](#71-pre-knowledge)
  - [Request DID Authentication](#72-request-did-authentication)
  - [Response DID Authentication](#73-response-did-authentication)
  - [Revoke DID Authentication](#74-revoke-did-authentication)
- [Privacy considerations](#8-privacy-considerations)
- [Security considerations](#9-security-considerations)
- [Verifiable Claims](#10-verifiable-claims)
  - [Profile](#101-profile)
  - [Agreement](#102-agreement)
  - [Proof of Holding](#104-proof-of-holding)
  - [Use Cases](#105-use-cases)
  - [Registry Blockchain](#106-registry-blockchain)
  - [APIs](#107-apis)

## 3. Abstract
OneITFarm DID is a new blockchain-based authentication method that follows all the requirements of W3C. Based on OneITFarm Wallet，our method provides a series of APIs and services for a fast and secure authentication process.

## 4. Motivation
The rapid development of Internet has provided unparalled convenience to the public, yet it is also inevitably bringing some potential problems. One of them is the leaking of private information that comes with traditional authentication systems. Taking advantage of blockchain's decentralization and security characteristics, we thus propose our secure authentication method.

## 5. DID
> Mainly used for declaring specifications for DID string.

### 5.1 Create DID
#### 1. Generate sercret key
##### 1. Choose one directly
Pick a random secret key or based on those that the entity has ("entity" here refers to OneITFarm Wallet).

##### 2. Create with ``appPk`` (use bip44 to calculate DID)
> Currently the creation of wallet accounts in OneITFarm Wallet is based on bip44.

- Process ``appDid`` with sh3
- Acquire the first 64 bits of hash.
- Split the those bits into two 32 bits: ``s1`` and ``s2``
- Obtain HD secrete key using  `m/44'/ABT'/S1'/S2'/address_index`

#### 2. Choose DID type

Choose `RoleType`,`KeyType` and `HashType`. DID is the first two bytes of of DID string in binary format. DID Type consists of the following three parts.

1. `RoleType`：first six bits

> To be expanded in the future.

- account = 0
- node = 1
- device = 2
- application = 3
- smart_contract = 4
- bot = 5
- asset = 6
- stake = 7
- validator = 8
- group = 9
- any = 63

2. `KeyType`：middle five bits

> Used for specifying the algorithm that converts secret keys to public keys.

- ED25519 = 0
- SECP256K1 = 1

3. `Hash`：last five bits

> Used for calculating public key hash function.

- keccak = 0
- sha3 = 1
- keccak_384 = 2
- sha3_384 = 3
- keccak_512 = 4
- sha3_512 = 5

As an example, DID Type `0x0C01` can be decoded like the following

```
+-------------+-----------+------------+
| 000011      | 00000     | 00001      |
+-------------+-----------+------------+
| application | ed25519   | sha3       |
+-------------+-----------+------------+

```

#### 3. Generate public key

Use the method corresponding to `KeyType` to convert secret key to public key.

For instance：`E4852B7091317E3622068E62A5127D1FB0D4AE2FC50213295E10652D2F0ABFC7`

#### 4. Obtain Hash of public key

`EC8E681514753FE5955D3E8B57DAEC9D123E3DB146BDDFC3787163F77F057C27`

#### 5. Obtain the first 20 bytes of the public key hash

`EC8E681514753FE5955D3E8B57DAEC9D123E3DB1`

#### 6. Add DID Type `0x0C01` before the hash of Step 5

`0C01EC8E681514753FE5955D3E8B57DAEC9D123E3DB1`

#### 7. Obtain the extended hash of Step 6 hash

`42CD815145538F8003586C880AF94418341F9C4B8FA0394876553F8A952C7D03`

#### 8. Pick the first 4 bytes of Step 7

`42CD8151`

#### 9. Generate binary DID String

Put the 4 bytes from Step 8 to the end of hash from Step 6 to get the DID String in binary format.
`0C01EC8E681514753FE5955D3E8B57DAEC9D123E3DB142CD8151`

#### 10. Encrypt the binary DID String

Encode the binary file with Base58 method and add `idg` before the result to get DID String
`idgNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr`

#### 11. The complete DID should look like this:

`did:idg:idgNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr`

### 5.2 Declare DID

DeclareDID is done by sending a transaction to the blockchain. Here's a sample transaction:

```json
{
  "hash": "36BBCA0115A52C0F43C42E84CAE368481A0F32B218380721E3DD2B0456D1D294",
  "tx": {
    "from": "z1RMrcjJVwuohBoqAsPaVvuDajQi1fDo8Qx",
    "itx": {
      "__typename": "DeclareTx",
      "data": null,
      "pk": "IWNMqz5IdsqxO0x9iqdlSfMvPkchVc3un8mmLXT_GcU",
      "type": {
        "address": "BASE58",
        "hash": "SHA3",
        "pk": "ED25519",
        "role": "ROLE_ACCOUNT"
      }
    },
    "nonce": 1,
    "signature": "E_BkPhw-WUpkTk5nn_WF4z-8huOBqjl-3vQ122TYCDQiahFlklVJT3I7YUwr8d-pi_mqMM0JKWB06ayJh3gODQ",
    "signatures": []
  }
}

```
:::tip
This is essentially putting the DID document on the blockchain.
:::
### 5.3 Read DID

Reading DID is as simple as sending a GRPC request to ABT network. The following is a description of the request's structure. `address` field is the DID to query. The omission of `keys` field will return the entire account status. `height` field can be used to locate DID documents of previous versions. If omitted, the latest document will be returned.

```js
message RequestGetAccountState {
  string address = 1;
  repeated string keys = 2;
  uint64 height = 3;
}

```

Response contains the DID document associated with this DID.

### 5.4 Update DID

Sending a transaction like this can update an associated DID document:

```json
{
  "hash": "36BBCA0115A52C0F43C42E84CAE368481A0F32B218380721E3DD2B0456D1D294",
  "tx": {
    "from": "z1RMrcjJVwuohBoqAsPaVvuDajQi1fDo8Qx",
    "itx": {
      "__typename": "UpdateTx",
      "data": "The new data to replace the existing one.",
      "pk": "IWNMqz5IdsqxO0x9iqdlSfMvPkchVc3un8mmLXT_GcU",
    },
    "nonce": 1,
    "signature": "E_BkPhw-WUpkTk5nn_WF4z-8huOBqjl-3vQ122TYCDQiahFlklVJT3I7YUwr8d-pi_mqMM0JKWB06ayJh3gODQ",
    "signatures": []
  }
}

```

Please note that old versions of DID documents are still stored on the chain due to chain's data structures. DID documents won't be updated with this operation. Rather, a new version will be put over existing ones.

### 5.5 Revoke DID

Revoking DID can be done by sending RevokeTx transaction to mark the DID document as revoked. Although the DID document will be considered revoked from the block containing the accepted transaction, the document is still stored on the chain instead of being erased.

```json
{
  "hash": "36BBCA0115A52C0F43C42E84CAE368481A0F32B218380721E3DD2B0456D1D294",
  "tx": {
    "from": "z1RMrcjJVwuohBoqAsPaVvuDajQi1fDo8Qx",
    "itx": {
      "__typename": "RevokeTx",
      "pk": "IWNMqz5IdsqxO0x9iqdlSfMvPkchVc3un8mmLXT_GcU",
    },
    "nonce": 1,
    "signature": "E_BkPhw-WUpkTk5nn_WF4z-8huOBqjl-3vQ122TYCDQiahFlklVJT3I7YUwr8d-pi_mqMM0JKWB06ayJh3gODQ",
    "signatures": []
  }
}

```

## 6. DID Document (DIDDoc)

### 6.1. Create DID Document

When the DID has been successfully created, it's time to create a corresponding DID ocument, the basic format of which is as follows:

```json
{
  "@context": "https://w3id.org/future-method/v1",
  "id": "did:example:123456789abcdefghi",
  "publicKey": [],
  "authentication": [],
  "service": []
}

```
:::tip
1. DID and the public key corresponding to its signature should be stored when a DID is created for the first time.
:::
### 6.2. Declare DID Document

The DID Document should be published to the chain after creation.

### 6.3 Read DID Document

Users sign DID with their private keys and DID Resolvers use public keys of the DID document for verification.

### 6.4 Update DID Document
> The core of updating a DID document is updating server endpoints.

1. Users sign ``server endpoint data`` with private keys. ``Server endpoint data`` is comprised of the following structures:
```
1. id：server endpoint id. Format is did#did-fragment 
2. type: this is of server endpoint type.
3. serviceEndpoint: server endpoint's detailed url.
4. desc: a description for server endpoint.
5. data: directly viewable information of server endpoint.
6. pk: server endpoint's pk.
```
2. Call interface to update the data after signing.
3. Update DID document with the data.

## 7. Workflow
> The following description is mainly for the procedure associated with DID auth. Using other server endpoints is similar.

Three processes are involved in using DID for the entire authentication protocol：``Pre-knowledge``，``Request DID Authentication`` and ``Response DID Authentication``. Each of them will be detailed in this section.

### 7.1 Pre-knowledge
``Pre-knowledge`` refers to the process of obtaining application information prior to starting the real authentication. The wallet needs to know the application's DID, public key and service endpoints beforehand. QR code or ``deep link`` can be used to provide this information.

#### 1. Here's an example of using QR code or ``deep link``
```
https://wallet.io/i?appPk=zBdZEnbDJTijVVCx4Nx68bzDPPMFwVizSRorvzSS3SGG2&appDid=did:idg:idgNK7PeUtemp5oAhJ4zNmGJ8rUoFnB1CtKfoU&action=requestAuth&url=https://example-application.io/auth/
```
- ``linkPath``: ``linkPath`` is located at the very beginning of a link. In this example, it is ``https://wallet.io/i``, used for locating Wallet. This part is configurable: SDK allows developers to register their own domains for applications. In other words, it is generated through OneITFarm.
  - If Wallet hasn't been installed, scanning the code with a third-party application or clicking the url will open an installation page.
  - If Wallet is installed, scanning with the app will obtain underlying parameters.
- ``apppk``：This is a Base59 encoded public key passed from an application to Wallet.
- ``appid``：It refers to the app's id in OneITFarm.
- ``appDid``：The application's DID.
- ``action``：It is used for telling Wallet what to do next. The action here should be ``requestAuth`` and Wallet will visit the url via ``GET`` method.
- ``url``：Wallet will use this x-www-form-urlencoded URL to start the Request DID Authentication process.

### 7.2 Request DID Authentication
Upon receiving the above information, Wallet will begin the process of requesting DID authentication in order to acquire the app-requested verifiable claims.
#### 1. Generate DID based on 3.1
#### 2. Encrypt user's DID using apppk.
#### 3. Call endpoint of requestAuth.
```
GET https://example-application.io/auth?userDid=encrypted_userDid
```
#### 4. A successful response returned by the request above will contain the following two fields:
1. ``appPk``：application's Base58-encoded public key
2. ``authInfo``：signed object in JWT format

::: tip An example:
```json
 {
   "appPk": "zBdZEnbDJTijVVCx4Nx68bzDPPMFwVizSRorvzSS3SGG2",
   "authInfo": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJleHAiOjE1NDg4MDM0MjIsImlhdCI6MTU0ODcwMzQyMiwiaXNzIjoiZGlkOmFidDp6Tkt0Q05xWVdMWVdZVzNnV1JBMXZuUnlrZkNCWllIWnZ6S3IiLCJuYmYiOjE1NDg3MDM0MjIsInJlcXVlc3RlZENsYWltcyI6eyJkb2N1bWVudHMiOlt7Imhhc2giOiJUaGUgaGFzaCBvZiB0aGUgZG9jdW1lbnQncyBjb250ZW50IiwidXJpIjoiaHR0cHM6Ly9kb2N1bWVudC0xLmlvIn0seyJoYXNoIjoiVGhlIGhhc2ggb2YgdGhlIGRvY3VtZW50J3MgY29udGVudCIsInVyaSI6ImlwZnM6Ly9kb2N1bWVudC0yIn1dLCJwcm9maWxlIjpbImZ1bGxOYW1lIiwicGhvbmUiLCJzaGlwcGluZ0FkZHJlc3MiXSwicHJvb2ZPZkhvbGRpbmciOlt7InRva2VuIjoidG9rZW4gbmFtZSAxIiwidmFsdWUiOjE4MDAwMDB9LHsidG9rZW4iOiJ0b2tlbiBuYW1lIDIiLCJ2YWx1ZSI6MTAwMDAwMH1dfSwicmVzcG9uc2VBdXRoVXJpIjoiaHR0cHM6Ly9leGFtcGxlLWFwcGxpY2F0aW9uL3Jlc3BvbnNlLWF1dGgifQ.RasZv6ydSxOBj3H726P8THeo4K4IAd7wapqrdE4hrOVRONByAHYK1kr7uAXASc_-Mw9ShD3IcqAuwnLiEkvHCQ"
 }
```
:::

The header and body of ``authInfo`` shown above can be decoded into:

```json
 {
   "alg": "Ed25519",
   "typ": "JWT"
 }
 {
   "iss": "did:abt:zNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr",
   "iat": 1548703422,
   "nbf": 1548703422,
   "exp": 1548803422,
   "appInfo": {
     "name": "The name of the application",
     "description": "The description of the application.",
     "logo": "https://example-application/logo"
   },
   "action": "responseAuth",
   "url": "https://example-application/auth",
   "requestedClaims": [
     {
       "type": "profile",
       "meta": {
         "description": "Please fill in basic information."
       },
       "items": ["fullName", "mobilePhone", "mailingAddress"]
     },
     {
       "type": "agreement",
       "meta": {
         "description": "The user data usage agreement."
       },
       "uri": "https://document-1.io",
       "hash": {
         "method": "sha256",
         "digest": "The hash result of the document's content"
       }
     },
     {
       "type": "agreement",
       "meta": {
         "description": "The service agreement"
       },
       "uri": "ipfs://document-2",
       "hash": {
         "method": "sha3",
         "digest": "The hash result of the document's content"
       }
     }
   ]
 }
```

- ``iss``: application's DID generated from appPk.
- ``iat``，``nbf`` and ``exp``: they follow the JWT standard.
- ``appInfo``: basic information of application.
- ``url``: a required field that Wallet uses when answering DID authentication.
- ``action``: Wallet's action in the next step. Here it should be ``responseAuth`` and Wallet will access the ``url`` with ``POST`` method.
- ``requestedClaims``: an optional field. It can ask users to identify themselves by returning this field if users are unknown to the application. Details of this is illustrated in a different section. The application can omit this field if needed. Upon receiving the response, the following authentication should be done by Wallet：
  1. Verify that ``iat`` is after sending the request. 
  2. Verify that the response is expired with ``exp``.
  3. Verify that the signature matches ``appPk`` and ``appPk`` matches ``appDid`` in ``iss`` field
  4. Wallet can (may under a user's request) request the application's metadata, such as ``trustLevel``, from a registery blockchain. WellLink provides ABT chain as a registery chain.
  5. Wallet can use ``trustLevel`` when displaying requested claim to user. Wallet should display a high risk mark on the entire page for applications whose ``appDid`` cannot be found on registery blockchain. High risk marks should also be displayed on application-requested verifiable claims whose required ``trustLevel`` is higher than ``appDid``.
### 7.3 Response DID Authentication
This is the last process of the entire workflow. Depending on whether the application is asking for verifiable claims, Wallet will either prompt users to fill in those claims and go to responseAuth endpoint or to go to the endpoint directly.

#### 1. Wallet should display all requested signature information and wait for user input.
#### 2. When the user has filled in everything, Wallet will use ``user_did`` to sign valid payloads with corresponding private keys, then send it back to the URL obtained from the DID authentication process in the following format.
```json
{
   "userPk": "",
   "userInfo": ""
 }
```
``userInfo`` above can be decoded into:
```json
{
   "alg": "Ed25519",
   "typ": "JWT"
 }
 {
   "iss": "userDid",
   "iat": "1548713422",
   "nbf": "1548713422",
   "exp": "1548813422",
   "requestedClaims": [
     {
       "type": "profile",
       "fullName": "Alice Bean",
       "mobilePhone": "123456789",
       "mailingAddress": {
         "addressLine1": "456 123th AVE",
         "addressLine2": "Apt 106",
         "city": "Redmond",
         "state": "WA",
         "postalCode": "98052",
         "country": "USA"
       }
     },
     {
       "type": "agreement",
       "uri": "https://document-1.io",
       "hash": {
         "method": "sha256",
         "digest": "The hash result of the document's content"
       },
       "agreed": true,
       "sig": "user's signature against the doc hash plus AGREED."
     },
     {
       "type": "agreement",
       "uri": "ipfs://document-2",
       "hash": {
         "method": "sha3",
         "digest": "The hash result of the document's content"
       },
       "agreed": false
     }
   ]
 }
```


#### 3. Application will respond like this if it accepts the authentication request:
```json
{
   "appPk": "E4852B7091317E3622068E62A5127D1FB0D4AE2FC50213295E10652D2F0ABFC7",
   "jwt": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJleHAiOiIxNTQ4ODk4ODM5IiwiaWF0IjoiMTU0ODg5NzAzOSIsImlzcyI6ImRpZDphYnQ6ek5LdENOcVlXTFlXWVczZ1dSQTF2blJ5a2ZDQlpZSFp2ektyIiwibmJmIjoiMTU0ODg5NzAzOSJ9.OtJDYOLEF_AtBD6qikE-zg-qnzrJnq1OQ2A9dgiLcWxWNZJjEQdUgei-ZfAB3QJ7zPFLxf-m33TS34WJ6cpbCg"
 }
```
```json
{
   "alg": "Ed25519",
   "typ": "JWT"
 }
 {
   "exp": "1548898839",
   "iat": "1548897039",
   "iss": "did:abt:zNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr",
   "nbf": "1548897039"
 }
```
#### 4. JWT returned in process above should be contained in header of the latter request as ``Authentication`` field.
#### 5. Now the authentication process is complete.
### 7.4 Revoke DID Authentication



## 8. Privacy considerations

The ways of creating, registering and managing DIDs in DID methods are designed to provide enhanced privacy, improved anonymity and reduced correlation risk.

- Keep personally-identifiable information (PII) off-ledger. Chains store signatures, not PII. A claim verifier asks the peer to be verified for the original data.

- DID Correlation Risks and Pseudonymous DIDs. Shown in the first step of [Request DID Authentication](/idg/DIDDesign.html#_1-2-request-did-authentication), generating application-specific DID  enforces pseudonymous DID and privacy across chains. A user might have multiple extended DIDs under one master DID and use those extended DIDs on different chains. The master DID would never, through any means, be exposed.

- DID Document Correlation Risks are lowered by isolating DID documents corresponding to extended DIDs of the same master DID.


## 9. Security considerations

The underlying blockchain is also designed to tackle the following security risks.

- Replay attacks
- Man-in-the-middle attacks
- Message insertion attacks
- Deletion attacks
- Modification attacks

Our blockchain-based implementation has covered every single requirement listed in W3C DID specification.

- security assumptions of distributed ledger topology
- policy mechanism used to prove DIDs are uniquely assigned
- integrity protection and update authentication for DID operations
- DID method-specific endpoint authentication

## 10. Verifiable Claims

Verifiable claims is a list of claim items. Every claim item must have a ``type`` field and can contain an optional ``meta`` field.

Until now, there are three kinds of verifiable claims:

- ``profile``：This can contain multiple universally-known predefined claim items, such as `firstName` and `birthday`.
- `agreement`：A peer may ask users to sign agreements.
- `proofOfHolding`： A peer may ask users to prove that they have either a certain amount of tokens or a certificate issued by a third party.

`meta` is an optional field which may contain, but not limited to, the following field:

- `description`: This is used for describing claim. Wallet can shown users this field.

### 10.1 Profile

Profile is the easiest verifiable claim for collecting users' basic information. It should contain the following fields:

- `type`：fixed to "profile".
- `meta`：an optional field.
- `items`：a list of predefined profile items.

When a peer needs profile claims, it should include a list of profile items in the response.

```json
{
    "requestedClaims": [
      {
        "type": "profile",
        "meta": {
          "description": "Please provide the basic information.",
        },
        "items": ["fullName", "mobilePhone", "mailingAddress"]
      }
    ]
  }

```

Upon receiving this response, Wallet should prompt the user to fill in data. Afterwards, Wallet should return the claims in the following format.

```json
{
    "requestedClaims": [
      {
        "type": "profile",
        "meta": {
          "description": "Please provide the basic information",
        },
        "fullName": "Alice Bean",
        "mobilePhone": "123456789",
        "mailingAddress": {
            "addressLine1": "456 123th AVE",
            "addressLine2": "Apt 106",
            "city": "Redmond",
            "state": "WA",
            "postalCode": "98052",
            "country": "USA"
          }
      }
    ]
  }

```

#### Predefined claim items

- billingAddress
- birthday
- companyAddress
- companyName
- driverLicense
- firstName
- fullName
- gender
- highestEducationDegree
- homeAddress
- homePhone
- languages
- lastName
- locale
- mailingAddress
- maritalStatus
- middleName
- mobilePhone
- nationalId
- nationality
- passport
- personalEmail
- photo
- placeOfBirth
- primaryOccupation
- socialSecurityNumber
- taxpayerIdNumber
- timezone
- workEmail
- workPhone

### 10.2 Agreement

Agreement is another common type of claim. It represents an agreement a peer asks users to sign. A claim of `agreeement` type should contain the following fields:

- `type`：fixed to "agreement".
- `meta`：optional field.
- `uri`：points to the content of agreement.
- `hash`：an object where the `method` subfield specifies the algorithm (sha3, sha256, etc) used and the `digest` subfield is the hash result.
- `agreed`：a boolean value added by Wallet to represent whether the user accepts the agreement.
- `sig`：the DSA signature of hash.

When peer wants user-signed agreements, it should add a list of claim item of agreement type in the response. Every claim item should have a `meta` that contains the agreement's URI and a summary of agreement content.

```json
{
    "requestedClaims": [
      {
        "type": "agreement",
        "meta": {
          "description": "The user data usage agreement.",
        },
        "uri": "https://document-1.io",
        "hash": {
          "method": "sha256",
          "digest": "The hash result of the document's content"
        }
      },
      {
        "type": "agreement",
        "meta": {
          "description": "The service agreement",
        },
        "uri": "ipfs://document-2",
        "hash": {
          "method": "sha3",
          "digest": "The hash result of the document's content"
        }
      }
    ]
  }

```

Wallet will prompt the user to sign the agreement after getting the response. Afterwards, Wallet shall submit a list of signed claim items to peer. If agreed by the user, Wallet shall add `AGREED` and user-signed `sig` field to the `response` field. If declined by user, Wallet will only need to add `DECLINED` to `response` field. No signature is needed under this circumstance.

```json
{
    "requestedClaims": [
      {
        "type": "agreement",
        "uri": "https://document-1.io",
        "hash": {
          "method": "sha256",
          "digest": "The hash result of the document's content"
        },
        "agreed": true,
        "sig": "user's signature against the doc digest plus AGREED."
      },
      {
        "type": "agreement",
        "uri": "ipfs://document-2",
        "hash": {
          "method": "sha3",
          "digest": "The hash result of the document's content"
        },
        "agreed": false
      }
    ]
  }

```

### 10.4 Proof of Holding

### 10.5 Use Cases

1. registration
2. login
3. signing documents
4. requesting/issuing certificates
5. VISA application
6. peer-to-peer information exchange

### 10.6 Registry Blockchain

Registry blockchain is where application DID registration should take place. As a decentralized agency, it tells Wallet regarding whether the application asking for can be trusted. A registry blockchain should provide at least the following information about the application: `trustLevel`.

#### Trust level

`trustLevel` is a number that provides insights into an application's relative reliability. It is the registry blockchain's responsibility to maintain the trust level of an application. If an application's done something despicable, it will be punished with a decreasing `trustLevel` resulting from voting.

### 10.7 APIs

#### 1. Wallet APIs

1. Creating a wallet containing public/private keys and address for OneITFarm applications.
2. Encrypting/decrypting auth-token.
3. Requesting to update and read a DID document.

#### 2. DID Service

1. Calculating and declaring DID.

2. Wallet-called functions for getting appDid's metadata.

3. Helper functions for constructing the encoded challenge to be signed.

4. Helper functions for verifying the signature and DID of a challenge.


```go
verify_challenge(challenge, pk)
verify_did(pk, did)
```
