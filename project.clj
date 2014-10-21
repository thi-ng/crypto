(defproject thi.ng/crypto "0.1.0-SNAPSHOT"
  :description  "Small Clojure lib to provide basic GPG keypair generation, encryption & decryption facilities"
  :url          "https://github.com/thi-ng/crypto"
  :license      {:name "Apache Software License 2.0"
                 :url "http://www.apache.org/licenses/LICENSE-2.0"
                 :distribution :repo}
  :scm          {:name "git"
                 :url "git@github.com:thi-ng/crypto.git"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.bouncycastle/bcpg-jdk15on "1.51"]])
