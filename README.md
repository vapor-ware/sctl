# Scuttle

<img src="sctl.svg" width="150" height="150" alt="sctl - pronounced scuttle" />


## Usage

Scuttle aims to help you prevent security breaches by keeping secrets in your
SCM in plain text. If you operate on Google Cloud, you don't have a lot of
options available to you out of the gate for managing secrets.

Scuttle uses KMS keys, and IAM policy to enforce the level of trust you need
at your trust boundaries. No plain text is stored in the repository, only cipher
text that is decryptable w/ an IAM user that has the appropriate permissions.

### Installation

```
TBD
```

### Manage Secrets

```
$ echo $SCTL_KEY
projects/my-project/locations/us/keyRings/operations-keyring/cryptoKeys/operations
$ sctl add foo bar
$ sctl list
FOO
$ cat .scuttle.json
[
 {
  "name": "FOO",
  "cypher": "CiQArcZm2GES73oHpipKV3UHUyFOUkPvWADrV/H6IssOIfVuh9wSKwDujG3UyRBnTFqciamPsK0x8UIaq6kzsYlhPoA9YHCzh0pd3KOJFpkvQqI=",
  "created": "2019-05-01T19:08:58.959335955-05:00"
 }
]
```

## Acknowledgements

Several tools like this have come before; sctl offers a polite hat-tip to
- [99designs/aws-vault](https://github.com/99designs/aws-vault)
- [banksimple/knox](#)
- [bitnami/sealed-secrets](https://github.com/bitnami/sealed-secrets)
