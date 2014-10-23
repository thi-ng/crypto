# thi.ng/crypto

A small collection of Clojure functions to provide basic GPG keypair generation, file/stream encryption & decryption.

## Dependencies

- [Bouncy Castle Crypto APIs](http://bouncycastle.org)
- [Unlimited strength JCE jurisdiction policy files](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

## Usage

Leiningen coordinates: `[thi.ng/crypto "0.1.0-SNAPSHOT"]`

```clojure
(require '[thi.ng.crypto.core :refer :all])

;; generate a new RSA keypair, private w/ identity & passphrase, save as armored files
(-> (rsa-keypair 2048)
    (generate-secret-key "alice@example.org" "hello")
    (export-keypair "alice.pub.asc" "alice.sec.asc" true))
; => nil

;; create dummy file
(spit "foo.txt" "hello world!")
; => nil

;; note: for files `encrypt-file` can be used alternatively,
;; but `encrypt-stream` is more flexible
(encrypt-stream "foo.txt" "foo.gpg" (public-key "alice.pub.asc"))
; => nil

;; decrypt with secret key & passphrase
(decrypt-stream "foo.gpg" "foo-decrypted.txt" (secret-key "alice.sec.asc") "hello")
; => #<BufferedOutputStream java.io.BufferedOutputStream@5dbe43af>

(slurp "foo-decrypted.txt")
; => "hello world!"
```

The generated keys can also be used with the `gpg` command line tool:

```
gpg --list-packet alice.pub.asc
:public key packet:
	version 4, algo 1, created 1413932095, expires 0
	pkey[0]: [2048 bits]
	pkey[1]: [17 bits]
	keyid: XXXXXXXXXXXXXXXX
:user ID packet: "alice@example.org"
:signature packet: algo 1, keyid XXXXXXXXXXXXXXXX
	version 4, created 1413932095, md5len 0, sigclass 0x10
	digest algo 2, begin of digest 2d 54
	hashed subpkt 2 len 4 (sig created 2014-10-21)
	subpkt 16 len 8 (issuer key ID XXXXXXXXXXXXXXXX)
	data: [2046 bits]
```

## License

Copyright © 2014 Karsten Schmidt

Distributed under the [Apache Software License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
