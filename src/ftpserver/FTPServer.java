package ftpserver;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FTPServer {

    private Scanner sc;
    private ServerSocket ssocket;
    private int port;
    private File FTPdir;
    private ArrayList<Thread> clients;

    public ServerSocket getSsocket() {
        return ssocket;
    }

    public void setSsocket(ServerSocket ssocket) {
        this.ssocket = ssocket;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public File getFTPdir() {
        return FTPdir;
    }

    public void setFTPdir(File FTPdir) {
        this.FTPdir = FTPdir;
    }

    /**
     * Prihvata u petlji klijente i za svakog novog klijenta kreira novu nit.
     * Iz petlje se moze izaci tako sto se na tastaturi otkuca Exit.
     */
    public void acceptClients() {
        boolean done = false;
        Socket client = null;
        Thread thr;
        while (!done) {
            try {
                client = this.ssocket.accept();
            } catch (IOException ex) {
                Logger.getLogger(FTPServer.class.getName()).log(Level.SEVERE, null, ex);
            }
            if (client != null) {
                //kreiraj novu nit (konstruktoru prosledi klasu koja implementira Runnable interfejs)
                thr = new Thread(new ConnectedFTPClient(client, FTPdir));
                //zapamti novo-kreiranog klijenta kako bi kasnije mogao da cekas da se svi terminiraju..
                this.clients.add(thr);
                //..i startuj ga
                thr.start();
            }
            /*
            //Proveri da li treba terminirati server aplikaciju (unosom stringa Exit sa tastature)
            if (this.sc.hasNextLine()){
                String line = this.sc.nextLine();
                if (line.equalsIgnoreCase("Exit"))
                    done = true;
            }
            */
            
        }
        
        /*
        //cekaj dok se svi klijenti ne opsluze
        for (Thread t : this.clients){
            try {
                t.join();
            } catch (InterruptedException ex) {
                Logger.getLogger(FTPServer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        */
        
    }

    public FTPServer(int port) {
        this.sc = new Scanner(System.in);
        this.clients = new ArrayList<>();
        try {
            this.port = port;
            this.ssocket = new ServerSocket(port);
        } catch (IOException ex) {
            Logger.getLogger(FTPServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * @param args broj porta servera i putanja FTP root direktorijuma
     */
    public static void main(String[] args) {
        //server program se poziva sa dva argumenta: broj porta i FTP direktorijum
        if (args.length < 2) {
            System.out.println("Morate proslediti dva parametra: port servera i FTP direktorijum.");
            System.exit(1);
        }
        FTPServer server = new FTPServer(Integer.parseInt(args[0]));
        server.setFTPdir(new File(args[1]));
        if (!server.getFTPdir().exists()) {
            System.out.println("Ne postoji direktorijum koji ste odabrali za FTP direktorijum.");
            System.exit(1);
        }

        //Prihvataj klijente u beskonacnoj petlji
        server.acceptClients();
        
    }

}
