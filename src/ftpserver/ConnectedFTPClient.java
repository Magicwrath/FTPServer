package ftpserver;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ConnectedFTPClient implements Runnable{
    
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";
    
    //response stringovi za uspesne razmene AES kljuca i IV
    public static final String RESP_AES_EXCHANGE_READY = "AcceptingAESKey"; //odgovor da je server spreman da primi AES kljuc
    public static final String RESP_RECIEVED_AES_KEY = "AESKeyRecieved";
    public static final String RESP_RECIEVED_IV = "InitializationVectorRecieved";
    public static final String RESP_WRONG_REQ = "WrongRequest";
    
    //Stringovi koji predstavljaju sve zahteve koje klijent moze da posalje
    //Ti zahtevi su: diskonekcija, prikaz fajlova i razmena novog AES kljuca
    //U slucaju zahteva preuzimanja fajla, bice poslat naziv fajla i njegova ekstenzija
    //Zbog toga ne postoji fiksan request String
    public static final String REQ_DISCONNECT = "Disconnect";
    public static final String REQ_NEW_AES_KEY = "SendingAESKey";
    public static final String REQ_SHOW_ALL_FILES = "RequestAllFiles";
    public static final String REQ_SHOW_PDF_FILES = "RequestPDFFiles";
    public static final String REQ_SHOW_JPG_FILES = "RequestJPGFiles";
    public static final String REQ_SHOW_TXT_FILES = "RequestTXTFiles";
    public static final String REQ_SEND_FILE = "SendFile";

    //atributi koji se koriste za komunikaciju sa klijentom
    private Socket socket;
    private InputStream is;
    private OutputStream os;
    
    //atributi koji se koriste za enkripciju/dekripciju
    private PublicKey publicKeyRSA;
    private PrivateKey privateKeyRSA;
    private SecretKey secretKeyAES;
    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private Cipher RSACipher;
    private Cipher AESCipher;
    private byte[] initializationVector; 
    
    //direktorijum FTP servera
    private File FTPDir;
    
    //getters and setters
    public InputStream getIs() {
        return is;
    }

    public void setIs(InputStream is) {
        this.is = is;
    }

    public OutputStream getOs() {
        return os;
    }

    public void setOs(OutputStream os) {
        this.os = os;
    }
    
    //Konstruktor klase, prima kao argument socket kao vezu sa uspostavljenim klijentom
    public ConnectedFTPClient(Socket socket, File FTPDir){
        this.socket = socket;
        this.privateKeyRSA = null;
        this.publicKeyRSA = null;
        this.FTPDir = FTPDir;
        try {
            this.keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        //duzina RSA kljuca je 1024 bita
        this.keyGen.initialize(1024);
        try {
            this.RSACipher = Cipher.getInstance("RSA");
            this.AESCipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.initializationVector = null;        
        
        //iz socket-a preuzmi InputStream i OutputStream
        try {
            this.is = this.socket.getInputStream();
            this.os = this.socket.getOutputStream();
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Napravi javni i tajni kljuc za RSA enkripciju/dekripciju
     */
    public void createKeys() {
        //Koristite keyGen kako biste napravili par kljuceva
        //postavite privateKeyRSA da bude referenca na tajni kljuc, a
        //publicKeyRSA da bude referenca na javni kljuc
        this.pair = keyGen.generateKeyPair();
        this.privateKeyRSA = this.pair.getPrivate();
        this.publicKeyRSA = this.pair.getPublic();
    }

    /**
     * Dekriptuj primljeni AES tajni kljuc enkriptovan javnim RSA kljucem
     * Za dekripciju koristi tajni RSA kljuc
     * @param msg enkriptovan tajni AES kljuc
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public void decryptSecretKeyAES(byte[] msg) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        //Koristite metodu init na RSACipher objektu uz mod Cipher.DECRYPT_MODE i koristeci privateKeyRSA za dekripciju
        this.RSACipher.init(Cipher.DECRYPT_MODE, this.privateKeyRSA);
        
        //dekriptujte primljenu poruku
        byte[] keyBytes = RSACipher.doFinal(msg);
        
        // iz primljene poruke rekonstruisite privatni kljuc za AES
        this.secretKeyAES = new SecretKeySpec(keyBytes, "AES");        
    }    
    
    
    /**
     * Dekriptuj primljeni inicijalizacioni vektor enkriptovan javnim RSA kljucem
     * Za dekripciju koristi tajni RSA kljuc
     * @param msg enkriptovan tajni IV
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public void decryptInitializationVector(byte[] msg) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        //Koristite metodu init na RSACipher objektu uz mod Cipher.DECRYPT_MODE i koristeci privateKeyRSA za dekripciju
        this.RSACipher.init(Cipher.DECRYPT_MODE, this.privateKeyRSA);
        
        //dekriptujte primljenu poruku
        byte[] keyBytes = RSACipher.doFinal(msg);
        
        // iz primljene poruke rekonstruisite IV za AES
        this.initializationVector = keyBytes;        
    }    
    
    /**
     * Dekriptuje niz bajtova na ulazu koristeci skriveni AES kljuc
     * @param input niz bajtova koji su primljeni od servera 
     * @return dekriptovan niz bajtova (po potrebi morace se konvertovati u string)
     * @throws Exception 
     */
    public byte[] do_AESDecryption(byte[] input) throws Exception{        
        //Koristite objekat IvParameterSpec klase sa initializationVector atributom 
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        
        //Inicijalizujte AESCipher u Cipher.DECRYPT_MODE modu sa secretKeyAES
        AESCipher.init(Cipher.DECRYPT_MODE, secretKeyAES, ivParameterSpec);
  
        //vrati dekriptovani ulaz koristeci prethodno inicijalizovan AESCipher
        return AESCipher.doFinal(input);
    }   
    
    /**
     * Enkriptuj ulazni niz bajtova koristeci skriveni AES kljuc
     * Kriptovani izlaz se salje serveru
     * @param input ulazni niz bajtova koji treba kriptovati
     * @return kriptovani izlaz spreman za slanje serveru
     * @throws Exception 
     */
    public byte[] do_AESEncryption(byte[] input) throws Exception{
        
        //Koristite instancu klase IvParameterSpec zajedno sa initializationVector atributom
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
  
        //inicijalizujte AESCipher u modu Cipher.ENCRYPT_MODE, zajedno sa secretKeyAES kljucem
        AESCipher.init(Cipher.ENCRYPT_MODE, secretKeyAES, ivParameterSpec);
  
        //vrati enkriptovani ulaz koristeci prethodno inicijalizovan AESCipher
        return AESCipher.doFinal(input);
    }
           
    /**
     * Salje nekriptovani javni kljuc za RSA koristeci OutputStream dobijen iz klijent socket-a
     */
    public void sendPublicKeyRSA(){
        try {        
            this.os.write(this.publicKeyRSA.getEncoded());
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Prima niz bajtova od klijenta i dekriptuje ih koristeci tajni AES kljuc
     * @return dekriptovani niz bajtova
     */
    public byte[] receiveAndDecryptMessage(){
        byte[] ret = null;
        try {
            //cekaj dok nesto ne stigne
            while ((this.is.available() <= 0) && this.socket.isConnected());
            //proveri duzinu pristiglog niza i napravi niz odgovarajuce duzine
            int len = this.is.available();
            byte[] receivedBytes = new byte[len];
            //preuzmi pristigle podatke
            this.is.read(receivedBytes);
            
            //Ako je klijent poslao nekodovanu poruku REQ_NEW_AES_KEY
            //zahteva novi AES kljuc
            //Ako je poslao REQ_DISCONNECT, zeli da se diskonektuje
            String msgString = new String(receivedBytes);
            if(msgString.equalsIgnoreCase(REQ_NEW_AES_KEY) || msgString.equalsIgnoreCase(REQ_DISCONNECT))
                return receivedBytes;
            
            //dekriptuj poruku koristeci tajni AES kljuc
            ret = do_AESDecryption(receivedBytes);
            
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        return ret;
    }
    
    /**
     * Kriptuje poruku i salje ka klijentu. Prilikom slanja se koristi OutputStream 
     * kao izlazna konekcija ka datom klijentu
     * @param plainMsg nekriptovana poruka koja treba da se salje
     */
    public void encryptAndSendMessage(byte[] plainMsg){
        byte [] encryptedMsg = null;
        try {
            encryptedMsg = do_AESEncryption(plainMsg);
        } catch (Exception ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            //posalji enkriptovanu poruku koristeci OutputStream os
            this.os.write(encryptedMsg);
            this.os.flush();
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Modeluje ponasanje servera u slucaju da je klijent
     * pritisnuo dugme "Posalji AES kljuc"
     * Ideja je da se ovo dugme moze vise puta stisnuti
     * a da server ispravno reaguje svaki put
     */
    void recieveEncryptedIVKeyAES () {
        //ako se pozove ova funkcija
        //znaci da je klijent stisnuo dugme "Posalji AES kljuc"
        //cime salje serveru poruku "SendingAESKey"
        //server treba da odgovori "AcceptingAESKey"
        try {
            this.os.write(RESP_AES_EXCHANGE_READY.getBytes());
            //sada server ceka da primi AES kljuc
            while(this.is.available() <= 0);
            //procitaj AES kljuc
            int len = this.is.available();
            byte[] encryptedKeyAES = new byte[len];
            this.is.read(encryptedKeyAES);
            //dekriptuj AES kljuc
            decryptSecretKeyAES(encryptedKeyAES);
            
            //posalji klijentu poruku "AESKeyRecieved"
            this.os.write(RESP_RECIEVED_AES_KEY.getBytes());
            
            //sada server ceka IV
            while(this.is.available() <= 0);
            //server cita IV
            len = this.is.available();
            byte[] encryptedIV = new byte[len];
            this.is.read(encryptedIV);
            //dekriptuj IV
            decryptInitializationVector(encryptedIV);
            
            //posalji klijentu poruku "InitializationVectorRecieved"
            this.os.write(RESP_RECIEVED_IV.getBytes());
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //Metoda koja iscitava imena fajlova iz FTPDir direktorijuma
    //u zavisnosti od fileTypeREGEX dodatka regularnom izrazu
    //npr "[a-zA-Z]+" za sve fajlove
    String listSpecifiedFiles(String fileTypeREGEX) {
        String fileREGEX = "[a-zA-Z0-9]+[a-zA-Z0-9._-]*.";
        //na generalni regex za fajlove, dodaj zeljenu ekstenziju za odredjeni tip
        fileREGEX += fileTypeREGEX;
        //kompajliraj regex
        Pattern filePattern = Pattern.compile(fileREGEX);
        
        //prodji kroz sve fajlove u FTPDir direktorijumu
        String requestedFileNames = "";
        for(File f : FTPDir.listFiles()) {
            //ako se regex poklapa, dodaj ime fajla u string requestedFileNames
            if(filePattern.matcher(f.getName()).matches())
                requestedFileNames += f.getName() + '\n';
        }
        
        return requestedFileNames;
    }
    
    /**
     * Metoda koja sluzi za pretrazivanje FTPDir direktorijuma
     * za zeljeni file sa imenom fileName
     * @param fileName String koji predstavlja naziv fajla koji
     * se zahteva
     * @return Vraca se File sa datim imenom. U slucaju da fajl ne postoji,
     * vraca se null
     */
    File fetchSpecifiedFile(String fileName) {
        String sep = System.getProperty("file.separator");
        File requestedFile = new File(FTPDir.getAbsolutePath() + sep + fileName);
        
        if(requestedFile.isFile())
            return requestedFile;
        
        return null;
    }
    
    /**
     * Metoda koja apstrahuje proces slanja String-a
     * kao odgovor na zahtev od klijenta
     */
    void sendResponseString(String response) {
        try {
            this.os.write(response.getBytes());
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * metoda koja apstrahuje proces primanja zahteva
     * od klijenta
     */
    @SuppressWarnings("empty-statement")
    String recieveRequestString() {
        try {
            while(this.is.available() <= 0);
            int msgLen = this.is.available();
            byte[] recievedBytes = new byte[msgLen];
            this.is.read(recievedBytes);
            String request = new String(recievedBytes);
            
            return request;
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
    
    /**
     * 
     */
    
    
    @Override
    public void run() {
        System.out.println("New connection!");
        byte[] recievedMsg; //cuva bajtove primljene poruke
        String requestMsg; //String format primljenih bajtova recievedMsg i predstavlja zahtev klijenta
        String requestedFileNames = ""; //imena fajlova odredjenog tipa koje zahteva klijent (npr .pdf fajlovi...)
        //server kreira RSA javni i tajni kljuc
        createKeys();
        //server salje javni RSA kljuc klijentu
        sendPublicKeyRSA();
        try {
            //server ceka na enkriptovani AES kljuc od klijenta
            //ovaj korak mora da se izvrsi prvo pre ostalih zahteva
            //odnosno prvi zahtev mora biti "SendingAESKey"
            //ISPRAVKA: klijentska aplikacija ce svakako obezbediti
            //da se prvo razmeni AES kljuc, tako da server ne mora
            //da brine da li ce mu prvi zahtev biti za AES kljuc
            /*
            do {
                requestMsg = recieveRequestString();
                
                //Ako je zahtev "SendingAESKey", pozovi funkciju za razmenu
                //AES kljuca, u suprotnom posalji "WrongRequest"
                if(requestMsg.equalsIgnoreCase(REQ_NEW_AES_KEY))
                    recieveEncryptedIVKeyAES();
                else
                    this.os.write(RESP_WRONG_REQ.getBytes());
            } while(!requestMsg.equalsIgnoreCase(REQ_NEW_AES_KEY));
            */

            do {
                //primi zahtev i dekriptuj ga (osim ako se posalje REQ_NEW_AES_KEY ili prethodno nisu razmenjeni kljucevi)
                if(this.secretKeyAES == null) {
                    //kljuc nije razmenjen, preuzmi neenkriptovanu poruku
                    requestMsg = recieveRequestString();
                } else {
                    //razmenjen je kljuc, poruka se dekriptuje (osim ako se posalje REQ_NEW_AES_KEY ili REQ_DISCONNECT)
                    recievedMsg = receiveAndDecryptMessage();
                    requestMsg = new String(recievedMsg);
                }
                
                if(requestMsg.equalsIgnoreCase(REQ_NEW_AES_KEY)) {
                    //razmena novog AES kljuca sa klijentom
                    recieveEncryptedIVKeyAES();
                } else if(requestMsg.equalsIgnoreCase(REQ_SHOW_ALL_FILES)) {
                    //posalji string koji sadrzi imena svih fajlova u FTP direktorijumu
                    requestedFileNames = listSpecifiedFiles("[a-zA-z]+");
                    //enkriptuj i posalji imena svih fajlova
                    encryptAndSendMessage(requestedFileNames.getBytes());
                } else if(requestMsg.equalsIgnoreCase(REQ_SHOW_PDF_FILES)) {
                    //posalji imena svih .pdf fajlova
                    requestedFileNames = listSpecifiedFiles("pdf");
                    encryptAndSendMessage(requestedFileNames.getBytes());
                } else if(requestMsg.equalsIgnoreCase(REQ_SHOW_JPG_FILES)) {
                    //posalji imena svih .jpg fajlova
                    requestedFileNames = listSpecifiedFiles("jpg");
                    encryptAndSendMessage(requestedFileNames.getBytes());
                } else if(requestMsg.equalsIgnoreCase(REQ_SHOW_TXT_FILES)) {
                    requestedFileNames = listSpecifiedFiles("txt");
                    encryptAndSendMessage(requestedFileNames.getBytes());
                } else if(!requestMsg.equalsIgnoreCase(REQ_DISCONNECT)) {
                    //ukoliko nije nijedan od definisanih request-ova
                    //to znaci da je korisnik poslao zahtev sa imenom fajla
                    //ili je generisao netacan request
                    File requestedFile = fetchSpecifiedFile(requestMsg);
                    if(requestedFile != null) {
                        //fajl postoji, posalji ga
                        //kreiraj BufferedInputStream koji cita bajtove fajla
                        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(requestedFile));
                        byte[] fileByteArray = new byte[(int) requestedFile.length()];
                       
                        //iscitaj bajtove fajla i smesti ih u fileByteArray
                        bis.read(fileByteArray, 0, fileByteArray.length);
                        
                        //posalji klijentu velicinu fajla u bajtovima (kao String)
                        encryptAndSendMessage(Integer.toString(fileByteArray.length).getBytes());
                        
                        //sacekaj odgovor od klijenta
                        String clientResp = new String(receiveAndDecryptMessage());
                        
                        if(clientResp.equalsIgnoreCase(REQ_SEND_FILE)) {
                            //posalji bajtove klijentu
                            encryptAndSendMessage(fileByteArray);
                            bis.close();
                        }
                    } else {
                        //fajl ne postoji, posalji RESP_WRONG_REQ
                        encryptAndSendMessage(RESP_WRONG_REQ.getBytes());
                        System.out.println("Ne postoji fajl!");
                    }
                }
            } while(!requestMsg.equalsIgnoreCase(REQ_DISCONNECT));
            
            //ako je server izasao iz do while petlje,
            //klijent je poslao REQ_DISCONNECT zahtev klikom
            //na dugme "Diskonektuj se"
            //Zatvori socket koji komunicira sa klijentom
            this.socket.close();
            this.is.close();
            this.os.close();
            System.out.println("Closed connection!");
        } catch (IOException ex) {
            Logger.getLogger(ConnectedFTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }    
}
