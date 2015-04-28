package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.util.Date;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Martin Banas
 */
public class RipTimers implements Runnable {

    private final RipManager ripManager;
    private Date lastUpdateSent;
    
    private final int updateTime = 30 * 1000;
    private final int invalidTime = 180 * 1000;
    private final int flushTime = 240 * 1000;
        
    public RipTimers(RipManager ripManager) {
        this.ripManager = ripManager;  
        lastUpdateSent = new Date();
        System.out.println("VYTVORIL SOM RIP TIMERS");
    }    

    /*
    Po 180s od posledneho update-u prejde routa do stavu invalid, nastavi sa jej metrika 16 a zacne sa pocitat holddown timer. Ak nepride 
    ziadny update ani do 240s, zaznam sa flushne z tabulky, teda sa prestane rozosielat. Ak vsak v stave invalid pride update na tuto cestu 
    
    Tlacidlo na vypnutie interfejsu, po vypnuti ak bolo aktivne rip tak presiri vsade ze je to poisoned
    
    po zmene ip adresy na interfejsi poslat vsade staru ip s metrikou 16, spolu s novou ip adresou LOL
    */
    @Override
    public void run() {
        Date actualDate;

        while (true) {
            actualDate = new Date();
            if (actualDate.getTime() - lastUpdateSent.getTime() > updateTime) {
                System.out.println("ABDEJTUJEM");
                ripManager.sendUpdateToAllIfaces();
                lastUpdateSent = new Date();
            }
            for (Iterator<RoutingTableItem> it = ripManager.getRoutingTable().getRoutingTableList().iterator(); it.hasNext();) {
                RoutingTableItem route = it.next();
                
                if (route.getRouteType().equals(RouteTypeEnum.DYNAMIC)) {
                    long timeDif = actualDate.getTime() - route.getLastUpdate().getTime();
                    
                    if (timeDif > invalidTime) {
                        route.setRouteState(RouteStateEnum.INVALID);                        
                    } else if (timeDif > flushTime) {
                        it.remove();
                    }
                }
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(RipManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

}
