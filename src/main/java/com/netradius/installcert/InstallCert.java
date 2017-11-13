package com.netradius.installcert;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import static com.netradius.commons.bitsnbytes.BitTwiddler.tohexstr;

/**
 * All code in this class was originally based on a post at
 * http://www.dzone.com/snippets/ssl-download-certificate-chain.
 *
 * @author Erik R. Jensen
 */
public class InstallCert {

  private static final String CACERTS_PATH = "/lib/security/cacerts";

  private static Options buildOptions() {
    Options options = new Options();

    options.addOption(Option.builder("h").longOpt("host").required().argName("host").hasArg()
        .desc("host to connect to").build());

    options.addOption(Option.builder("p").longOpt("port").argName("port").hasArg()
        .desc("port to connect to (default 443)").build());

    options.addOption(Option.builder("s").longOpt("passphrase").argName("passphrase").hasArg()
        .desc("passphrase for key store (default changeit)").build());

    options.addOption(Option.builder("k").longOpt("keystore").argName("keystore").hasArg()
        .desc("keystore to add to (default is the JVM cacerts file))").build());

    options.addOption(Option.builder("n").longOpt("noprompt").argName("noprompt")
        .desc("do not prompt to save").build());

    options.addOption(Option.builder("b").longOpt("backup").argName("backup")
        .desc("backup keystore before save").build());

    options.addOption(Option.builder("H").longOpt("help")
        .desc("print this menu").build());

    return options;
  }

  private static void printHelp(Options options) {
    HelpFormatter formatter = new HelpFormatter();
    formatter.printHelp("java -jar InstallCert.jar", options);
  }

  private static int getPort(CommandLine line) {
    int port = 443;
    if (line.hasOption("port")) {
      try {
        port = Integer.parseInt(line.getOptionValue("port"));
      } catch (NumberFormatException x) {
        System.err.println("port value must be numeric");
        System.exit(1);
      }
    }
    return port;
  }

  private static String getPhassephrase(CommandLine line) {
    return line.hasOption("passphrase") ? line.getOptionValue("passphrase") : "changeit";
  }

  private static File getKeyStoreFile(CommandLine line) {
    File file;
    if (line.hasOption("keystore")) {
      file = new File(line.getOptionValue("keystore"));
    } else {
      File dir = new File(System.getProperty("java.home") + "/lib/security");
      file = new File(dir, "jssecacerts");
      if (!file.exists()) {
        file = new File(dir, "cacerts");
      }
    }
    if (!file.exists()) {
      System.err.println("Cannot open " + file.getAbsolutePath());
      System.exit(1);
    }
    if (!file.canWrite()) {
      System.err.println("Cannot write to " + file.getAbsolutePath());
      System.exit(1);
    }
    return file;
  }

  private static KeyStore openKeyStore(File keyStoreFile, String passphrase) {
    InputStream in = null;
    try {
      in = new FileInputStream(keyStoreFile);
      KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
      ks.load(in, passphrase.toCharArray());
      return ks;
    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException x) {
      System.err.println("unable to open key store: " + x.getMessage());
      x.printStackTrace();
      System.exit(1);
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (IOException x) {
          // do nothing
        }
      }
    }
    return null;
  }

  private static class SavingTrustManager implements X509TrustManager {

    private final X509TrustManager tm;
    private X509Certificate[] chain;

    SavingTrustManager(X509TrustManager tm) {
      this.tm = tm;
    }

    public X509Certificate[] getAcceptedIssuers() {
      return tm.getAcceptedIssuers();
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      tm.checkClientTrusted(chain, authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      this.chain = chain;
    }
  }

  private static X509Certificate[] getCertificateChain(KeyStore ks, String host, int port) {
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
          .getDefaultAlgorithm());
      tmf.init(ks);
      X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
      SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
      context.init(null, new TrustManager[]{tm}, null);
      SSLSocketFactory factory = context.getSocketFactory();

      System.out.println("opening connect to " + host + ":" + port);
      try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
        socket.setSoTimeout(10000); // 10 seconds
        System.out.println("starting SSL handshake");
        socket.startHandshake();
      } catch (IOException x) {
        System.err.println("error communicating with host: " + x.getMessage());
        x.printStackTrace();
        System.exit(2);
      }

      X509Certificate[] chain = tm.chain;
      if (chain == null) {
        System.err.println("failed to obtain certificate chain");
        System.exit(2);
      }
      System.out.println("obtained " + chain.length + " certificate(s) from host");
      return chain;

    } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException x) {
      System.err.println("error setting up SSL connection: " + x.getMessage());
      x.printStackTrace();
      System.exit(2);
    }
    return null;
  }

  private static void addCertificateChain(KeyStore ks, X509Certificate[] chain, String host,
                                          boolean noprompt) {
    try {
      MessageDigest sha1 = MessageDigest.getInstance("SHA1");
      MessageDigest md5 = MessageDigest.getInstance("MD5");
      for (int i = 0; i < chain.length; i++) {
        X509Certificate cert = chain[i];
        System.out.println();
        System.out.println("Certificate " + i + ":");
        System.out.println("  Subject: " + cert.getSubjectDN());
        System.out.println("  Issuer:  " + cert.getIssuerDN());
        System.out.println("  SHA1:    " + tohexstr(sha1.digest(cert.getEncoded())));
        System.out.println("  MD5:     " + tohexstr(md5.digest(cert.getEncoded())));
        System.out.println();
        boolean save = noprompt || promptForSave("add certificate to keystore");
        if (save) {
          String alias = host + "-" + i;
          System.out.println("adding certificates to keystore as alias " + alias);
          ks.setCertificateEntry(alias, cert);
        } else {
          System.out.println("certificate not added to keystore");
        }
        System.out.println();
        sha1.reset();
        md5.reset();
      }
    } catch (NoSuchAlgorithmException | CertificateEncodingException | KeyStoreException x) {
      System.err.println("an error occurred adding certiticate to the keystore: "
          + x.getMessage());
      x.printStackTrace();
      System.exit(1);
    }
  }

  private static boolean promptForSave(String msg) {
    try {
      BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
      System.out.println(msg + " (Y/n) [Y]");
      String line = reader.readLine().trim();
      return line.equals("Y") || line.equals("y") || line.isEmpty();
    } catch (IOException x) {
      System.err.println("error reading stdin: " + x.getMessage());
      x.printStackTrace();
    }
    return false;
  }

  private static void backup(File keyStoreFile) {
    String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
    File bak = new File(keyStoreFile.getParentFile(), keyStoreFile.getName() + "." + timestamp);
    try {
      System.out.println("backing up " + keyStoreFile.getAbsolutePath() + " to "
          + bak.getAbsolutePath());
      Files.copy(keyStoreFile.toPath(), bak.toPath(), StandardCopyOption.COPY_ATTRIBUTES);
    } catch (IOException x) {
      System.err.println("error saving backup file: " + x.getMessage());
      x.printStackTrace();
    }
  }

  private static void save(File keyStoreFile, KeyStore ks, String passphrase) {
    try (OutputStream out = new FileOutputStream(keyStoreFile)) {
      ks.store(out, passphrase.toCharArray());
      System.out.println("\nkeystore written successfully, exiting");
    } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException x) {
      System.err.println("error saving keystore: " + x.getMessage());
      x.printStackTrace();
    }
  }

  public static void main(String[] args) {

    Options options = buildOptions();
    CommandLineParser parser = new DefaultParser();
    CommandLine line = null;
    try {
      line = parser.parse(options, args);
    } catch (ParseException x) {
      System.err.println(x.getMessage());
      printHelp(options);
      System.exit(1);
    }

    if (line.hasOption("help")) {
      printHelp(options);
      System.exit(0);
    }

    boolean noprompt = line.hasOption("noprompt");

    String host = line.getOptionValue("host");
    int port = getPort(line);
    String passphrase = getPhassephrase(line);
    File keyStoreFile = getKeyStoreFile(line);
    KeyStore ks = openKeyStore(keyStoreFile, passphrase);
    X509Certificate[] chain = getCertificateChain(ks, host, port);

    addCertificateChain(ks, chain, host, noprompt);

    boolean save = noprompt || promptForSave("save modified keystore");
    if (save) {
      if (line.hasOption("backup")) {
        backup(keyStoreFile);
      }
      save(keyStoreFile, ks, passphrase);
    } else {
      System.out.println("not saving keystore, exiting");
    }
  }

}
