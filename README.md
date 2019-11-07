# Scuttle

/ˈskədl/


<img src="sctl.svg" width="150" height="150" alt="sctl - pronounced scuttle" />

Icon made by [Gregor Cresnar](https://www.flaticon.com/authors/gregor-cresnar) from www.flaticon.com

## About Scuttle

Scuttle aims to help you prevent security breaches by keeping secrets out of
SCM in plain text. If you operate on Google Cloud, you don't have a lot of
options available to you out of the gate for managing secrets.

Scuttle uses KMS keys, and IAM policy to enforce the level of trust you need
at your trust boundaries. No plain text is stored in the repository, only cipher
text that is decryptable with an IAM user that has the appropriate permissions.

SCTL is not End2End encryption, instead SCTL is more of an envelope, in which
you store secrets until they are needed, and those secrets should only remain
available in plain text while the operation that needs them is active.

#### Why the name scuttle?

It's less interesting than you think. I'm a fan of short cli commands, and
sctl is short hand for "secrets-ctl", which when pronounced out loud sounds
like "scuddle" (i'm a kube cuddle person) - ergo: "scuttle".


### Installation

**Homebrew**:

> Currently only x86 linux/mac are supported.

Install sctl
```
brew tap vapor-ware/formula
brew install vapor-ware/formula/sctl
```

**Snap Packages**:
> We tried snaps, at this time its not a suitable release channel for sctl.
> We are open to attempting again in the future.

**Pipeline Releases**:

> Currently only x86 arch, linux/mac/windows are published.

Download the latest stable release from the [Releases](https://github.com/vapor-ware/sctl/releases)
listing for your platform/arch.

Untarball the release `tar xvfz sctl_version_Linux_x86_64.tar.gz`

Install the `sctl` binary somewhere in $PATH, eg:

`sudo install sctl /usr/local/bin/sctl` - this will move the binary to `/usr/local/bin/sctl` and chmod the binary 755

**From Source**:

You'll need at least go 1.11 (for go modules), a valid `$GOPATH`, and should have the GOPATH
bin path appended to `$PATH`

```
go get -u github.com/vapor-ware/sctl
```


### Configuration

Configuration consists of 2 steps:


#### Authentication
You can configure sctl's authentication in one of two ways.

1) `GOOGLE_APPLICATION_CREDENTIALS` - via env. You set this environment variable to a filepath containing your credentials. Which can be any serviceAccount or authorized User for example.

2) `sctl credential add` will prompt you for a client configuration JSON. Ask your sctl administrator to provide this value if you're unsure what to enter. Once input, a link will be output to your terminal to visit. Open the link, log in to google, and Grant sctl's KMS scope authentication request. Copy/paste the resulting authorization code back into your terminal.

#### Key Configuration

Optionally, you may set an ENV var to provide the value for your key parameter. This is useful if you
work in a small department and use the same key consistently. Otherwise this step may be skipped and you can pass the `--key` flag to any command that supports it.
 
```
export SCTL_KEY=projects/my-project/locations/us/keyRings/my-keyring/cryptoKeys/my-key
```

### Usage

To get help with any command and show usage details, sctl responds to the `--help`
flag, or simply run sctl without any arguments.

```
$ sctl add foo
Enter the data you want to encrypt. END with CTRL+D
bar
$ sctl list
FOO
$ cat .scuttle.json
[
 {
  "name": "FOO",
  "cypher": "CiQArcZm2GES73oHpipKV3UHUyFOUkPvWADrV/H6IssOIfVuh9wSKwDujG3UyRBnTFqciamPsK0x8UIaq6kzsYlhPoA9YHCzh0pd3KOJFpkvQqI=",
  "created": "2019-05-01T19:08:58.959335955-05:00"
  "encoding": "base64"
 }
]
# sctl run helmfile diff
```

### Rotate state / re-key

As you deprecate/disable older KMS key revisions, it can be prudent to migrate
a statefile of encrypted secrets. This can be a daunting task if undertaken one
by one. To ease the migration between versions (and different keys). The re-key
function was introduced in 1.0.0.

```
sctl re-key --newKey projects/new-project/locations/us/keyRings/new-keyring/cryptoKeys/new-key

Rotated entry for FOO
Rotated entry for BAR
```

Note: this operation attempts to be ATOMIC, and if an error occurs, the state
may be incompletely translated. This can be confirmed if the sctl state file
is versioned in VCS where you can easily diff the contents.

Note: the base64 data, and createdOn date's should be different if the entry
was updated.

## Acknowledgements

Several tools like this have come before; sctl offers a polite hat-tip to
- [99designs/aws-vault](https://github.com/99designs/aws-vault)
- [bitnami/sealed-secrets](https://github.com/bitnami/sealed-secrets)

## Reference Reading

- [Create Symmetric KMS Keys](https://cloud.google.com/kms/docs/creating-keys)
- [Encrypt/Decrypt with a symmetric CloudKMS Key](https://cloud.google.com/kms/docs/encrypt-decrypt)
- [Secret Storage with Cloud KMS](https://cloud.google.com/kms/docs/store-secrets)
- [Cloud KMS Roles](https://cloud.google.com/iam/docs/understanding-roles#cloud-kms-roles)
