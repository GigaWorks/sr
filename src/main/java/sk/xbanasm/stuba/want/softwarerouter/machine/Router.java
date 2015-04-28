
package sk.xbanasm.stuba.want.softwarerouter.machine;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import sk.xbanasm.stuba.want.softwarerouter.forwarding.Forwarder;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import sk.xbanasm.stuba.want.softwarerouter.routing.RoutingTable;
import sk.xbanasm.stuba.want.softwarerouter.routing.RouteTypeEnum;
import sk.xbanasm.stuba.want.softwarerouter.packetanalyzer.ReceivedPacket;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.gui.RouterGui;
import sk.xbanasm.stuba.want.softwarerouter.routing.GatewayItem;
import sk.xbanasm.stuba.want.softwarerouter.routing.RipManager;

/**
 *
 * @author Martin Banas
 */
public class Router {
    
    private final RouterGui routerGui;
    private final List<Interface> interfaces;
    private final Queue<ReceivedPacket> receivedPacketsQueue = new ConcurrentLinkedQueue<>();
    private final Queue<ReceivedPacket> receivedArpPacketsQueue = new ConcurrentLinkedQueue<>();
    private final Queue<ReceivedPacket> receivedRipPacketsQueue = new ConcurrentLinkedQueue<>();
    private Forwarder forwarder;
    private RoutingTable routingTable;
    private RipManager ripParser;
    
    public Router(RouterGui routerGui) throws IOException {
        this.routerGui = routerGui;
        this.routingTable = new RoutingTable();
        this.interfaces = new ArrayList<>();
        List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs                  
        //actualDate = new Date();
        //System.out.println("\n[Starting..] Time: " + sdf.format(actualDate));

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }
        
        int i = 0;
        for (PcapIf device : alldevs) {  
            System.out.println(i + ". " + Utils.macByteArrayToHexString(device.getHardwareAddress()) + " " + device.getName());
            interfaces.add(new Interface("fastEthernet 0/" + i, device, receivedPacketsQueue, receivedArpPacketsQueue, receivedRipPacketsQueue, routingTable));            
            i++;
        }
        this.forwarder = new Forwarder(interfaces, receivedPacketsQueue, receivedArpPacketsQueue, routingTable);
        new Thread(forwarder).start();  
        
        this.ripParser = new RipManager(interfaces, receivedRipPacketsQueue, routingTable);
        new Thread(ripParser).start();
        
        loadConfig();
    }
    
    private void loadConfig() throws FileNotFoundException, UnknownHostException {
        JsonObject configJO;
        JsonArray interfacesJA;
        JsonArray staticRoutesJA;
        FileInputStream fileInputStream;

        JsonReaderFactory jrf = Json.createReaderFactory(null);

        fileInputStream = new FileInputStream(new File("F:/VI.semester/WAN/zadanie/Maven project/SoftwareRouter/src/main/resources/routerConfigFile.json"));
        try (JsonReader jsonReader = jrf.createReader(fileInputStream)) {
            configJO = jsonReader.readObject();

            interfacesJA = configJO.getJsonArray("interfaces");
            
            for (int i = 0; i < interfaces.size(); i++) {               
                interfaces.get(i).noShutdown(interfacesJA.getJsonObject(i).getString("ip"), interfacesJA.getJsonObject(i).getString("mask"));
            }
            
            staticRoutesJA = configJO.getJsonArray("staticRoutes");
            
            for (int i = 0; i < staticRoutesJA.size(); i++) {
                routingTable.addRoute(RouteTypeEnum.STATIC, Utils.ipAddressToByteArray(staticRoutesJA.getJsonObject(i).getString("net")), Utils.ipAddressToByteArray(staticRoutesJA.getJsonObject(i).getString("mask")), null, new GatewayItem(Utils.ipAddressToByteArray(staticRoutesJA.getJsonObject(i).getString("gateway")), 0));
            }
        }
    }

    public List<Interface> getInterfaces() {
        return interfaces;
    }  

    public Forwarder getForwarder() {
        return forwarder;
    }    

    public RoutingTable getRoutingTable() {
        return routingTable;
    }

    public RipManager getRipManager() {
        return ripParser;
    }
    
}
