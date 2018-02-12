InstallCert
==============================================

The goal of this project is to create a Jar file InstallCert.jar which downloads certificate chain from a remote host
and adds the certificates to a local keystore.

## Where do I download InstallCert?
You can clone the repository in a location where there is enough free space to hold the repository source code.

In order to Clone this repository, please use the following command at a location where you intend to download 
InstallCert:

git clone https://github.com/netradius/install-cert


## How do I build InstallCert?
In order to build this project, you need to have the Java SE 8 (JDK) installed - You should be able to run "java 
-version" from the command line.

Inorder to build the jar, you need to open a command prompt, navigate to the same directory as the top level pom.xml 
file in the project and then run the following command

./mvnw clean package

## How do I run InstallCert?
Inorder to run the jar, you need to open a command prompt, navigate to the same directory as the top level pom.xml 
file in the project and then run the following command

java -jar ./target/install-cert-X.X.X-SNAPSHOT.jar -h HOST_NAME_OR_IP –k PATH_TO_JAVA_TRUSTSTORE –s 
PASSWORD_FOR_TRUSTSTORE -p PORT_TO_CONNECT


where following are the options you need to add while running above command

-b,--backup                    backup keystore before save
-h,--host <host>               host to connect to
-H,--help                      print this menu
-k,--keystore <keystore>       keystore to add to (default is the JVM
                                cacerts file))
-n,--noprompt                  do not prompt to save
-p,--port <port>               port to connect to (default 443)
-s,--passphrase <passphrase>   passphrase for key store (default
                                changeit)

Example

java -jar ./target/install-cert-1.0.0-SNAPSHOT.jar -h google.com -k $(/usr/libexec/java_home)
/jre/lib/security/cacerts -s changeit -p 443

Sample Output:
Abhijeets-MacBook-Pro:install-cert abhi$ java -jar ./target/install-cert-1.0.0-SNAPSHOT.jar -h google.com -k 
/Test/cacerts -s changeit -p 443
opening connect to google.com:443
starting SSL handshake
obtained 3 certificate(s) from host

Certificate 0:
  Subject: CN=*.google.com, O=Google Inc, L=Mountain View, ST=California, C=US
  Issuer:  CN=Google Internet Authority G2, O=Google Inc, C=US
  SHA1:    7311351267DE95C6A749E664439E009F10562D95
  MD5:     B0470908284F7B5978EB301B2C1375FE

add certificate to keystore (Y/n) [Y]
Y
adding certificates to keystore as alias google.com-0


Certificate 1:
  Subject: CN=Google Internet Authority G2, O=Google Inc, C=US
  Issuer:  CN=GeoTrust Global CA, O=GeoTrust Inc., C=US
  SHA1:    A6120FC0B4664FAD0B3B6FFD5F7A33E561DDB87D
  MD5:     17866CCBD224BD2FF9DF48B95118F935

add certificate to keystore (Y/n) [Y]
Y
adding certificates to keystore as alias google.com-1


Certificate 2:
  Subject: CN=GeoTrust Global CA, O=GeoTrust Inc., C=US
  Issuer:  OU=Equifax Secure Certificate Authority, O=Equifax, C=US
  SHA1:    7359755C6DF9A0ABC3060BCE369564C8EC4542A3
  MD5:     2E7DB2A31D0E3DA4B25F49B9542A2E1A

add certificate to keystore (Y/n) [Y]
Y
adding certificates to keystore as alias google.com-2

save modified keystore (Y/n) [Y]
Y

keystore written successfully, exiting

[NetRadius, LLC](https://www.netradius.com/)
