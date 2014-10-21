(ns thi.ng.crypto.core
  (:require
   [clojure.java.io :as io])
  (:import
   [org.bouncycastle.jce.provider
    BouncyCastleProvider]
   [org.bouncycastle.bcpg
    ArmoredOutputStream
    HashAlgorithmTags]
   [org.bouncycastle.openpgp
    PGPObjectFactory
    PGPPublicKeyRingCollection
    PGPSecretKeyRingCollection
    PGPPublicKey PGPSecretKey
    PGPPublicKeyRing PGPSecretKeyRing
    PGPKeyPair PGPPublicKey
    PGPSecretKey PGPSignature
    PGPCompressedData PGPCompressedDataGenerator
    PGPEncryptedData PGPEncryptedDataList PGPEncryptedDataGenerator
    PGPLiteralData PGPLiteralDataGenerator
    PGPUtil]
   [org.bouncycastle.openpgp.operator.bc
    BcPGPDataEncryptorBuilder
    BcPGPDigestCalculatorProvider
    BcPBESecretKeyDecryptorBuilder
    BcPublicKeyDataDecryptorFactory
    BcPublicKeyKeyEncryptionMethodGenerator]
   [org.bouncycastle.openpgp.operator.jcajce
    JcaPGPContentSignerBuilder
    JcaPGPDigestCalculatorProviderBuilder
    JcaPGPKeyPair
    JcePBESecretKeyEncryptorBuilder]
   [java.util Date]
   [java.io InputStream OutputStream ByteArrayOutputStream]
   [java.security
    KeyPair
    KeyPairGenerator
    SecureRandom
    Security]))

(Security/addProvider (BouncyCastleProvider.))

(defn generate-keypair*
  [^String algorithm]
  (fn [bits]
    (let [gen (doto (KeyPairGenerator/getInstance algorithm "BC")
                (.initialize (int bits)))]
      (.generateKeyPair gen))))

(def rsa-keypair     (generate-keypair* "RSA"))
(def dsa-keypair     (generate-keypair* "DSA"))
(def elgamal-keypair (generate-keypair* "ELGAMAL"))

(defn generate-secret-key
  [^KeyPair pair ^String ident ^String pass]
  (let [sha1 (.. (JcaPGPDigestCalculatorProviderBuilder.)
                 (build)
                 (get HashAlgorithmTags/SHA1))
        pair (JcaPGPKeyPair. PGPPublicKey/RSA_GENERAL pair (Date.))
        sign (-> pair (.getPublicKey) (.getAlgorithm)
                 (JcaPGPContentSignerBuilder. HashAlgorithmTags/SHA1))
        enc  (-> (JcePBESecretKeyEncryptorBuilder. PGPEncryptedData/CAST5 sha1)
                 (.setProvider "BC")
                 (.build (char-array pass)))]
    (PGPSecretKey.
     PGPSignature/DEFAULT_CERTIFICATION
     pair
     ident
     sha1
     nil
     nil
     sign
     enc)))

(defn export-keypair
  [^PGPSecretKey key out-pub out-sec armored?]
  (let [outp (io/output-stream out-pub)
        outs (io/output-stream out-sec)]
    (with-open [outp (if armored? (ArmoredOutputStream. outp) outp)
                outs (if armored? (ArmoredOutputStream. outs) outs)]
      (-> key (.encode outs))
      (-> key (.getPublicKey) (.encode outp)))))

(defn public-key
  [path]
  (with-open [in (io/input-stream path)]
    (->> (for [ring (-> (PGPUtil/getDecoderStream in)
                        (PGPPublicKeyRingCollection.)
                        (.getKeyRings)
                        (iterator-seq))
               key  (-> ring (.getPublicKeys) (iterator-seq))]
           key)
         (some #(if (.isEncryptionKey ^PGPPublicKey %) %)))))

(defn secret-key
  [path]
  (with-open [in (io/input-stream path)]
    (->> (for [ring (-> (PGPUtil/getDecoderStream in)
                        (PGPSecretKeyRingCollection.)
                        (.getKeyRings)
                        (iterator-seq))
               key  (-> ring (.getSecretKeys) (iterator-seq))]
           key)
         (some
          #(if (and (.isSigningKey %)
                    (not (.. % (getPublicKey) (isRevoked))))
             %)))))

(defn extract-private-key
  [^PGPSecretKey key ^chars pass]
  (.extractPrivateKey
   key (-> (BcPGPDigestCalculatorProvider.)
           (BcPBESecretKeyDecryptorBuilder.)
           (.build pass))))

(defn file->zipped-bytes
  [src]
  (with-open [bytes (ByteArrayOutputStream.)
              com (PGPCompressedDataGenerator. PGPCompressedData/ZIP)]
    (PGPUtil/writeFileToLiteralData (.open com bytes) PGPLiteralData/BINARY (io/file src))
    (.close com)
    (.toByteArray bytes)))

(defn stream->zipped-bytes
  [in name buf-size]
  (let [buf (byte-array buf-size)]
    (with-open [in    (io/input-stream in)
                ld    (PGPLiteralDataGenerator.)
                bytes (ByteArrayOutputStream. buf-size)]
      (with-open [com (PGPCompressedDataGenerator. PGPCompressedData/ZIP)
                  out (.open ld (.open com bytes)
                             PGPLiteralData/BINARY name (Date.) (byte-array buf-size))]
        (io/copy in out :buffer-size buf-size))
      (.toByteArray bytes))))

(defn encrypt-bytes
  [bytes dest ^PGPPublicKey pub-key]
  (let [enc   (doto (BcPGPDataEncryptorBuilder. PGPEncryptedData/AES_256)
                (.setWithIntegrityPacket true)
                (.setSecureRandom (SecureRandom.)))
        gen   (doto (PGPEncryptedDataGenerator. enc)
                (.addMethod (BcPublicKeyKeyEncryptionMethodGenerator. pub-key)))]
    (with-open [out (.open gen (io/output-stream dest) (long (alength bytes)))]
      (.write out bytes))))

(defn encrypt-file
  [src dest ^PGPPublicKey pub-key]
  (encrypt-bytes (file->zipped-bytes src) dest pub-key))

(defn encrypt-stream
  [src dest ^PGPPublicKey pub-key]
  (encrypt-bytes (stream->zipped-bytes src (str (java.util.UUID/randomUUID)) 0x1000) dest pub-key))

(defn decrypt
  [src out sec-key pass]
  (with-open [in  (io/input-stream src)
              out (io/output-stream out)]
    (let [pk  (extract-private-key sec-key (char-array pass))
          in  (-> in (PGPUtil/getDecoderStream) (PGPObjectFactory.))
          enc (.nextObject in)
          enc (if (instance? PGPEncryptedDataList enc) enc (.nextObject in))
          pbe (-> enc (.getEncryptedDataObjects) (.next))
          msg (-> (.getDataStream pbe (BcPublicKeyDataDecryptorFactory. pk))
                  (PGPObjectFactory.)
                  (.nextObject))
          msg (if (instance? PGPCompressedData msg)
                (-> msg (.getDataStream) (PGPObjectFactory.) (.nextObject))
                msg)]
      (if (instance? PGPLiteralData msg)
        (with-open [ld (.getInputStream ^PGPLiteralData msg)]
          (io/copy ld out :buffer-size 0x1000)
          out)))))
