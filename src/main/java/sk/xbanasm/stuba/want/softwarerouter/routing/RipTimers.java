package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Martin Banas
 */
public class RipTimers implements Runnable {

    private final RipManager ripManager;
    private Date lastUpdateSent;
        
    public RipTimers(RipManager ripManager) {
        this.ripManager = ripManager;  
        lastUpdateSent = new Date();
        System.out.println("VYTVORIL SOM RIP TIMERS");
    }        

    @Override
    public void run() {
        Date actualDate;

        while (true) {
            actualDate = new Date();
            if (actualDate.getTime() - lastUpdateSent.getTime() > 30000) {
                System.out.println("ABDEJTUJEM");
                ripManager.sendUpdateToAllIfaces();
                lastUpdateSent = new Date();
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(RipManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

}
