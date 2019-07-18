# 中台did方法规范
## 1. DID-Auth-Protocol
此文档为中台 DID-Auth-Protocol 的详细阐述，用作定义使用细节，以供使用者参考。

## 2. Table of Contents
- [DID-Auth-Protocol](/didserver/DIDDesign.html#_1-did-auth-protocol)
- [Table of Contents](/didserver/DIDDesign.html#_2-table-of-contents)
- [Abstract](/didserver/DIDDesign.html#_3-abstract)
- [Motivation](/didserver/DIDDesign.html#_4-motivation)
- [DID](/didserver/DIDDesign.html#_5-did)
  - [Create DID](/didserver/DIDDesign.html#_5-1-create-did)
  - [Declare DID](/didserver/DIDDesign.html#_5-2-declare-did)
  - [Read DID](/didserver/DIDDesign.html#_5-3-read-did)
  - [Update DID](/didserver/DIDDesign.html#_5-4-update-did)
  - [Revoke DID](/didserver/DIDDesign.html#_5-5-revoke-did)
- [DID Document](/didserver/DIDDesign.html#_6-did-dcoument)
  - [创建 DID Document](/didserver/DIDDesign.html#_6-1-创建did-document)
  - [Declare DID Document](/didserver/DIDDesign.html#_6-2-declare-did-document)
  - [Read DID Document](/didserver/DIDDesign.html#_6-3-read-did-document)
  - [Update DID Document](/didserver/DIDDesign.html#_6-4-update-did-document)
- [Workflow](/didserver/DIDDesign.html#_7-workflow)
  - [Pre-knowledge](/didserver/DIDDesign.html#_7-1-pre-knowledge)
  - [Request DID Authentication](/didserver/DIDDesign.html#_7-2-request-did-authentication)
  - [Response DID Authentication](/didserver/DIDDesign.html#_7-3-response-did-authentication)
  - [Revoke DID Authentication](/didserver/DIDDesign.html#_7-4-revoke-did-authentication)
- [Privacy considerations](/didserver/DIDDesign.html#_8-privacy-considerations)
- [Security considerations](/didserver/DIDDesign.html#_9-security-considerations)
- [Verifiable Claims](/didserver/DIDDesign.html#_10-verifiable-claims)
  - [Profile](/didserver/DIDDesign.html#_10-1-profile)
  - [Agreement](/didserver/DIDDesign.html#_10-2-agreement)
  - [Proof of Holding](/didserver/DIDDesign.html#_10-4-proof-of-holding)
  - [Use Cases](/didserver/DIDDesign.html#_10-5-use-cases)
  - [Registry Blockchain](/didserver/DIDDesign.html#_10-6-registry-blockchain)
  - [APIs](/didserver/DIDDesign.html#_10-7-apis)

## 3. Abstract
中台DID（去中心化身份认证）是一种新的基于区块链的认证方法，符合W3C的各项规范。此方法基于中台钱包，并对外提供一系列的API和服务，能便捷、安全地提供认证。

## 4. Motivation
因特网的迅速发展给人们带来了便利，却也无可避免地带来一些潜在问题。传统的认证系统带来的个人隐私泄漏就是其中之一。利用区块链去中心化和安全的特点，我们提出的验证方法因此而生。

## 5. DID
> 主要用于定义didstring相关的规范

### 5.1 Create DID
#### 1. 生成sercret key
##### 1. 直接选择一个
随机选择一个secret key 或者基于实体已有的（这里的实体指的是中台钱包）

##### 2. 使用应用的pk创建(使用bip44来计算did)
> 目前中台钱包是基于bip44来创建钱包钱包账户的

- 使用sh3处理appdid
- 获取前64位hash
- 将64位hash 拆分为两个32的位s1，s2
- 使用  `m/44'/WLK'/S1'/S2'/address_index`  来生成 HD sercret key

#### 2. 选择DID type

选择`RoleType`,`KeyType`,`HashType`,DID是 DID string的二进制格式的前两位bytes DID Type 由如下三部分组成：

1. RoleType：前6位bits

> 后期按需扩展

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

2. KeyType：中间5位bits

> 用于指定secret key 转换 public key 的 算法

- ED25519 = 0
- SECP256K1 = 1

3. Hash：最5位bits

> 用于计算公钥哈希的Hash函数

- keccak = 0
- sha3 = 1
- keccak_384 = 2
- sha3_384 = 3
- keccak_512 = 4
- sha3_512 = 5

例如：DID Type ：`0x0C01`  可以做如下解析

```
+-------------+-----------+------------+
| 000011      | 00000     | 00001      |
+-------------+-----------+------------+
| application | ed25519   | sha3       |
+-------------+-----------+------------+

```


#### 3. 获得public key

使用KeyType对应的方式来讲secret key 转换为 publick key。

例如：`E4852B7091317E3622068E62A5127D1FB0D4AE2FC50213295E10652D2F0ABFC7`

#### 4. 获取public key 的Hash

`EC8E681514753FE5955D3E8B57DAEC9D123E3DB146BDDFC3787163F77F057C27`

#### 5. 获取public key hash 的前20 bytes

`EC8E681514753FE5955D3E8B57DAEC9D123E3DB1`

#### 6. 在5中获得hash前添加DID Type：`0x0C01`

`0C01EC8E681514753FE5955D3E8B57DAEC9D123E3DB1`

#### 7. 获取6中hash的扩展hash

`42CD815145538F8003586C880AF94418341F9C4B8FA0394876553F8A952C7D03`

#### 8. 取7中前4个bytes

`42CD8151`

#### 9. 生成二进制的 DID String

将8得到的4个bytes放到6中得到hash的后边。得到DID String的二进制格式
`0C01EC8E681514753FE5955D3E8B57DAEC9D123E3DB142CD8151`

#### 10. 加密二进制的DID String

使用 Base58 方法进行二进制的文件编码。完成之后再起前边添加`idg`  得到DID String
`idgNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr`

#### 11 完整的DID如下

`did:idg:idgNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr`



### 5.2 Declare DID

DeclareDID是通过向区块链发送transaction来完成的。以下是一个示例transaction。

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
这个的本质是将did document 放在区块链上
:::
### 5.3 Read DID

要阅读DID，只需要向ABT网络发送GRPC请求。请求的结构描述如下。address字段是要查询的DID。如果省略keys字段，则将返回整个帐户状态。height字段可用于检索旧版本的DID文档。如果省略，将返回最新的一个。

```js
message RequestGetAccountState {
  string address = 1;
  repeated string keys = 2;
  uint64 height = 3;
}

```

响应包含与此DID关联的DID文档

### 5.4 Update DID

要更新DID的关联DID文档，可以发送这样的transaction：

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

值得一提的是，由于链使用的数据结构的性质，旧版本的DID文档仍然存储在链中。因此，此操作不会更新DID文档，而是将新版本放在现有文档上。


### 5.5 Revoke DID

要撤消DID文档，可以发送RevokeTx transaction以将DID文档标记为已撤销。 DID文档将被视为已从接受交易的块中撤销。这并不意味着DID文档被删除，它们仍然存储在链中

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
## 6. DID Dcoument
### 6.1. 创建DID Document

创建DID成功之后创建与之对应的DID Document，基础的DID Document格式如下。

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
1. 首次创建did 需要存入did 和did签名对应的公钥
:::
### 6.2. Declare DID Document

创建完成之后会将DID Document 发布到链上

### 6.3 Read DID Document

用户使用私钥签名did，DID Resolvers 使用did document 的公钥进行认证。

### 6.4 Update DID Document
> DID Document更新的核心意义在于更新Server endpoints

1. 用户使用私钥签名server entpoint data 
server entpoint data包含以下结构
```
1. id：server endpoint id，格式为：did#did-fragment 
2. type: server endpoint 类型
3. serviceEndpoint: server endpoint具体的url
4. desc: server endpoint 描述
5. data: server endpoint 直接可视信息。
6. pk: server endpoint的pk。
```

2. 调用接口更新签名后的数据。
3. 将数据更新到did document上，
## 7. Workflow
> 主要讲解针对did auth的相关流程。其他server endpoint 同理。

使用did作为整个身份验证协议包含三个过程：``Pre-knowledge``，``Request DID Authentication``和``Response DID Authentication``。我们将在本节中详细说明其中的每一个。
### 7.1 Pre-knowledge
``Pre-knowledge``是指钱包在真实认证开始之前获取应用程序信息的过程。钱包需要提前知道应用程序的DID，应用程序的公钥及其服务端点。该信息可以包含在由应用程序提供的QR码或``deep link``链接中。
#### 1. 以下是QR码内容或``deep link``的示例
```
https://wallet.io/i?appPk=zBdZEnbDJTijVVCx4Nx68bzDPPMFwVizSRorvzSS3SGG2&appDid=did:idg:idgNK7PeUtemp5oAhJ4zNmGJ8rUoFnB1CtKfoU&action=requestAuth&url=https://example-application.io/auth/
```
- linkPath: linkPath位于链接的开头，在此示例中为``https://wallet.io/i``，用于定位钱包。这部分是可配置的，SDK允许开发人员为应用程序注册自己的域。或者说这部分是在中台生成的
  - 未安装应用时使用第三方应用扫码或者点击url时引导到对应的应用安装界面
  - 已安装时，使用应用进行扫码获取其后边的参数
- apppk：应用的publick key，使用base58编码。它将传递给Wallet。
- appid：应用在中台的appid
- appDid：应用的DID
- action：告诉钱包应该在下一步中执行的操作。这里的动作应该是requestAuth，钱包将使用GET方法来访问url
- url：此参数是x-www-form-urlencoded URL，钱包将使用该URL来启动后者的请求DID身份验证过程。
### 7.2 Request DID Authentication
钱包收集上一节中描述的信息后，它启动请求DID身份验证过程。此过程的主要目的是获取应用程序请求的可验证声明。
#### 1. 基于3.1生成did
#### 2. 使用apppk加密用户的did。
#### 3. 调用requestAuth的 endpoint。
```
GET https://example-application.io/auth?userDid=encrypted_userDid&userpk=userpk
```
::: tip
endpoint 接收到消息后进行验证did身份。验证did与userpk是否一致。验证成功后执行下一步
:::
#### 4. 上述请求成功返回结果包含以下两个字段
1. apppk：应用的public key，Base58 编码
2. authInfo：jwt格式的签名对象

::: tip 示例:
```json
 {
   "appPk": "zBdZEnbDJTijVVCx4Nx68bzDPPMFwVizSRorvzSS3SGG2",
   "authInfo": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJleHAiOjE1NDg4MDM0MjIsImlhdCI6MTU0ODcwMzQyMiwiaXNzIjoiZGlkOmFidDp6Tkt0Q05xWVdMWVdZVzNnV1JBMXZuUnlrZkNCWllIWnZ6S3IiLCJuYmYiOjE1NDg3MDM0MjIsInJlcXVlc3RlZENsYWltcyI6eyJkb2N1bWVudHMiOlt7Imhhc2giOiJUaGUgaGFzaCBvZiB0aGUgZG9jdW1lbnQncyBjb250ZW50IiwidXJpIjoiaHR0cHM6Ly9kb2N1bWVudC0xLmlvIn0seyJoYXNoIjoiVGhlIGhhc2ggb2YgdGhlIGRvY3VtZW50J3MgY29udGVudCIsInVyaSI6ImlwZnM6Ly9kb2N1bWVudC0yIn1dLCJwcm9maWxlIjpbImZ1bGxOYW1lIiwicGhvbmUiLCJzaGlwcGluZ0FkZHJlc3MiXSwicHJvb2ZPZkhvbGRpbmciOlt7InRva2VuIjoidG9rZW4gbmFtZSAxIiwidmFsdWUiOjE4MDAwMDB9LHsidG9rZW4iOiJ0b2tlbiBuYW1lIDIiLCJ2YWx1ZSI6MTAwMDAwMH1dfSwicmVzcG9uc2VBdXRoVXJpIjoiaHR0cHM6Ly9leGFtcGxlLWFwcGxpY2F0aW9uL3Jlc3BvbnNlLWF1dGgifQ.RasZv6ydSxOBj3H726P8THeo4K4IAd7wapqrdE4hrOVRONByAHYK1kr7uAXASc_-Mw9ShD3IcqAuwnLiEkvHCQ"
 }
```
:::

上面显示的authInfo的标题和正文部分解码为:

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

- iss: 应用程序从appPk生成的DID
- iat，nbf和exp：遵循JWT标准。
- appInfo: 应用程序的基础信息
- url: 响应DID身份验证过程中钱包将使用的必填字段.
- action: 告诉钱包下一步应该采取什么行动。这里应该是responseAuth和wallet将使用POST方法来访问url。
- requestedClaims: 是一个可选的提交。如果用户不知道该应用程序，它可以要求用户通过返回此文件来标识自己。我们将在一节中说明这个细节1如果需要，该应用程序也可以省略此处。 得到回复后，钱包应该进行以下验证：
  1. 验证iat是否晚于发送请求。
  2. 使用exp验证响应是否已过期。
  3. 验证签名是否与appPk匹配，以及appPk是否与iss字段中的appDid匹配。
  4. 钱包可以（可以根据用户的请求）向注册表区块链询问应用程序的元数据，例如trustLevel。WellLink提供ABT链作为注册链。
  5. 在向用户显示请求的声明时，wallet可以使用trustLevel。对于在注册表区块链上找不到appDid的应用程序，钱包应该使整个页面具有高风险标记。如果应用程序要求可验证的声明，其所需的trust_level高于appDids'，则钱包应显示具有高风险标记的声明。
### 7.3 Response DID Authentication
这是整个工作流程的最后一个过程。取决于应用程序是否需要可验证claims，钱包将提示用户填写所请求的claims，然后转到responseAuth端点或直接在此过程中转到端点ßß

#### 1. 电子钱包应向用户显示所有请求的签名信息并等待用户的输入
#### 2. 用户填写所有数据后，钱包使用usr_did的相应密钥对有效负载进行签名，然后将其发送回请求DID身份验证过程中获取的URL，格式如下。
```json
{
   "userPk": "",
   "userInfo": ""
 }
```
上面的userInfo解码为:
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


#### 3. 如果应用程序接受身份验证请求，则会响应:
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
#### 4. 在上述步骤中返回的JWT应作为身份验证字段包含在后一个请求的标头中。
#### 5. 此时，验证过程完成。
### 7.4 Revoke DID Authentication


## 8. Privacy considerations

如何在 DID方法中创建，注册和管理DID的方法旨在提供增强的隐私，改进的匿名性和降低的相关风险。

- 保持个人身份信息（PII）的分类帐。 PII不存储在链上，只存储签名。当验证者需要验证声明时，它会要求对等体验证原始数据。

- DID相关风险和匿名DID 如 [Request DID Authentication](/idg/DIDDesign.html#_1-2-request-did-authentication)步骤1中所示，如何生成特定于应用程序的DID的方式在不同链中强制执行假名DID和隐私。用户在一个主DID下具有多个扩展DID，并且在不同链中使用不同的扩展DID。主DID永远不会以任何方式公开曝光。

- DID Document 相关风险 隔离了相同主DID的不同扩展DID的DID文档


## 9. Security considerations

底层区块链还确保了以下安全风险：

- 重播攻击
- 中间人攻击
- 消息插入攻击
- 删除攻击
- 修改攻击

我们基于区块链的实现已经考虑了W3C DID规范中列出的以下每个要求:

- 分布式总账拓扑的安全假设
- 用于证明DID的唯一分配的策略机制
- DID操作的完整性保护和更新身份验证
- DID特定于方法的端点身份验证

## 10. Verifiable Claims

Verifiable claims 是一个 claim 条目的列表。每个claim项目必须具有归档type，并且可以选择具有meta归档。

到目前为止，有三种类型的Verifiable claims：

- profile：配置文件可以包含多个众所周知的预定义声明项，例如firstName，birthday等
- agreement：对等方可以要求用户签署协议。
- proofOfHolding： 对等方可以要求用户证明他们拥有一定数量的令牌或拥有第三方颁发的证书。

`meta`是一个可选字段，可以包含但不限于以下字段：

- description: 用于描述claim。电子钱包可以向用户显示此字段。

### 10.1 Profile

Profile是用于收集用户基本信息的最简单的verifiable claims。profile文件cliam类型应具有以下字段：

- type：固定为“profile”。
- meta：可选字段
- items：预定义的配置文件项列表。

当peer需要profile claims，它应该向响应中添加配置文件项列表：

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

收到此回复后。钱包应该提示用户填写数据。后者，钱包应按以下格式返回声明：

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

###  10.2 Agreement

协议是另一种常用的claim类型。它代表同行要求用户签署的协议。协议声明类型应包含以下字段：

- type：固定为“agreement”
- meta：可选字段
- uri：URI指向协议的内容
- hash：方法子字段指定使用的算法（sha3，sha256等）的对象，摘要子字段是散列结果。
- agreed：钱包添加的布尔值，表示用户是否同意该协议。
- sig：哈希的DSA签名

当对等方想要用户签署协议时，它应该在响应中添加协议类型的声明项列表。每个声明项都有一个`meta`，其中包含协议的URI以及协议内容的摘要：

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

当看到此响应时，钱包应提示用户签署协议。后者，钱包应该将签名的索赔项目列表提交给同行。如果用户同意，则钱包应添加具有AGREED的响应字段以及包含用户签名的sig字段。如果用户拒绝，那么钱包只需要添加带有DECLINED的响应字段。在这种情况下不需要签名。

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

###  10.4 Proof of Holding

###  10.5 Use Cases

1. 注册
2. 登录
3. 签署文档
4. 要求/签发证书
5. 申请签证
6. 点对点信息交换

###  10.6 Registry Blockchain

Registry blockchain是应该注册应用程序DID的地方。它是权力下放的权威机构，为钱包提供指导，无论其要求的应用程序是否值得信赖。注册表区块链应至少提供应用程序的以下信息：trustLevel

#### Trust level

信任级别是一个相对显示应用程序可信度的数字。注册表区块链负责维护应用程序的信任级别。例如，应用程序可以在ABT链上放置ABT令牌以增加其信任级别。如果应用程序做了一些邪恶的事情，它将受到惩罚，其信任级别将通过投票而下降

###  10.7 APIs

#### 1. Wallet APIs

1. 为中台应用生成一个钱包，包含公私钥和address
2. 加密解密 auth-token
3. 请求更新 和 读取 did document

#### 2. DID Service

1. 计算并声称did

2. 钱包调用的函数来获取appDid的元数据

3. 辅助函数用于构造要签名的编码质询

4. 辅助函数用于验证质询的签名和DID


```go
verify_challenge(challenge, pk)
verify_did(pk, did)
```

