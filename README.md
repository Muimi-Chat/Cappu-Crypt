# Cappu Crypt

![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white)
![Spring](https://img.shields.io/badge/spring-%236DB33F.svg?style=for-the-badge&logo=spring&logoColor=white)
![Postgres](https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)

CappuCrypt is a really simple key management API service.

### Why?

It's great for really small and simple projects, where encryption security is a concern. But not to an extend where you have to concern yourself with key rotations or access control policies.

### How easy is it to use?

It just comes with 3 API endpoints, one for decrypting, one for encrypting, and one for key deletion.

```sh
# API Request to Encrypt content with AES_256
$ curl -X POST -F 'encryptionType=AES_256' -F 'content=Hello, World!' -H 'Authorization: <SNIP>' localhost:8080/crypt/encrypt
{
  "status": "SUCCESS",
  "id": "2d01a221-c2ff-4d29-ae9e-b79c7bdcb337",
  "encryptedContent": "JC5TeDwH+ugji+yBKmuXlqdHgqUw8dY8Z9MXoqODlZiqseDZgD0/AGo=",
  "messages": [
    "ID was not provided, creating new ID.",
    "Created new key for 2d01a221-c2ff-4d29-ae9e-b79c7bdcb337 with encryption method: AES_256"
  ],
  "notes": [
    "NEW_ID_CREATED",
    "ENCRYPTED_WITH_AES_256"
  ]
}

# Decrypt it back!
$ curl -X POST -F 'id=2d01a221-c2ff-4d29-ae9e-b79c7bdcb337' -F 'content=JC5TeDwH+ugji+yBKmuXlqdHgqUw8dY8Z9MXoqODlZiqseDZgD0/AGo=' -H 'Authorization: <SNIP>' localhost:8080/crypt/decrypt
{
  "status": "SUCCESS",
  "decryptedContent": "Hello, World!",
  "messages": [
    "ID found in database. Using existing key.",
    "Decrypted content with encryption type: AES_256"
  ],
  "notes": [
    "DECRYPTED_WITH_AES_256"
  ]
}
```

### Features

* Supports AES-128, AES-192 and AES-256.
    * Uses GCM Mode for all encryption, supporting optional metadata for integrity checks.
* An Authorization Key to make API requests.
* A master key to encrypt all the keys.
* One simple Springboot application, so you can place it in a back-facing server without exposure to the outside world!

# Getting Started

See [how to deploy](https://github.com/wqyeo/Cappu-Crypt/wiki/Deploying), or [documentations on API endpoints](https://github.com/wqyeo/Cappu-Crypt/wiki/API-Endpoints) on the wiki.
