package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.math.BigInteger;
import java.net.UnknownHostException;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.header.MyHeader;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.Ethernet.EthernetType;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.gui.RouterGui;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;
import sk.xbanasm.stuba.want.softwarerouter.packetanalyzer.ReceivedPacket;

/**
 *
 * @author Martin Banas
 */
public class RipManager implements Runnable {

    private boolean activeRipRouting = false;
    private Queue<ReceivedPacket> receivedRipPacketsQueue;
    private RoutingTable routingTable;
    private ReceivedPacket ripPacket;

    private List<Interface> activeRipIfacesList = new ArrayList<>();
    private List<Interface> connectedPorts;
    private RipTimers ripTimers;
    private Date lastUpdateSent = new Date();

    private final byte[] mcastMac = {(byte) 0x01, (byte) 0x00, (byte) 0x5e, (byte) 0x00, (byte) 0x00, (byte) 0x09}; //01:00:5e:00:00:09
    private final byte[] mcastIp = {(byte) 0xE0, (byte) 0x00, (byte) 0x00, (byte) 0x09}; //224.0.0.9
    private final int ripRequest = 1;
    private final int ripResponse = 2;
    private final int ipAfi = 2;
    private final int requestAfi = 0;

    public RipManager(List<Interface> connectedPorts, Queue<ReceivedPacket> receivedRipPacketsQueue, RoutingTable routingTable) {
        this.connectedPorts = connectedPorts;
        this.receivedRipPacketsQueue = receivedRipPacketsQueue;
        this.routingTable = routingTable;

        ripTimers = new RipTimers(this);
        new Thread(ripTimers).start();
    }

    @Override
    public void run() {
        while (true) {
            while (!receivedRipPacketsQueue.isEmpty()) {
                ripPacket = receivedRipPacketsQueue.poll();
                System.out.println("Dosral som rip paketlik " + !ripPacket.getIpv4Header().getTcpUdpAnalyser().isRequest());
                /*
                 rozanalyzovat by si mal tie rip paketle v analyzatore kua
                 */
                if (ripPacket.getIpv4Header().getTcpUdpAnalyser().isRequest()) {
                    parseRequest();
                } else {
                    parseResponse();
                }
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(RipManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void parseRequest() {
        int entriesCount = ripPacket.getIpv4Header().getTcpUdpAnalyser().getEntriesCount();
        int entriesOffset = ripPacket.getIpv4Header().getTcpUdpAnalyser().getEntriesOffset();

        if ((ripPacket.getPacket().getUShort(entriesOffset + 1)) == 2) {

        }
    }

    private void parseResponse() {
        int entriesCount = ripPacket.getIpv4Header().getTcpUdpAnalyser().getEntriesCount();
        int entriesOffset = ripPacket.getIpv4Header().getTcpUdpAnalyser().getEntriesOffset();

        System.out.println("RIP od: " + ripPacket.getIpv4Header().getSrcIp() + "  pocet zaznamov: " + entriesCount);
        for (int i = 0; i < entriesCount; i++) {
            RipEntry ripEntry = new RipEntry(ripPacket.getPacket(), entriesOffset);

            if (ripEntry.getAfi() == 2) {
                try {
                    if (Arrays.equals(ripEntry.getNextHop(), Utils.ipAddressToByteArray("0.0.0.0"))) {
                        ripEntry.setNextHop(ripPacket.getIpv4Header().getSrcIpBA());
                    }

                    //System.out.println("ip: " + Utils.ipByteArrayToString(ripPacket.getPacket().getByteArray(entriesOffset + 4, 4)) + "  mask: " + Utils.ipByteArrayToString(ripPacket.getPacket().getByteArray(entriesOffset + 8, 4)) + "  gateway: " + Utils.ipByteArrayToString(gateway) + "  metric: " + new BigInteger(ripPacket.getPacket().getByteArray(entriesOffset + 16, 4)).intValue());
                    routingTable.addRoute(RouteTypeEnum.DYNAMIC, ripEntry.getIpAddress(), ripEntry.getSubnetMask(), null, new GatewayItem(ripEntry.getNextHop(), ripEntry.getMetric()));
                } catch (UnknownHostException ex) {
                    Logger.getLogger(RipManager.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            entriesOffset += 20;
        }
    }

    public void activateRipOnIface(byte[] network) throws UnknownHostException {
        for (RoutingTableItem item : routingTable.getRoutingTableList()) {
            if (item.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
                if (Arrays.equals(item.getNetworkAddressBA(), network)) {
                    item.getOutputInterface().setRipActivated(true);
                    activeRipIfacesList.add(item.getOutputInterface());

                    JMemoryPacket ripRequestPacket = createPacket(1, item.getOutputInterface().getMacAddressBA(), item.getOutputInterface().getIpAddressBA(), ripRequest);
                    writeRipEntryToPacket(ripRequestPacket, 46, requestAfi, Utils.ipAddressToByteArray("0.0.0.0"), Utils.ipAddressToByteArray("0.0.0.0"), 16);

                    item.getOutputInterface().sendPacket(ripRequestPacket.getByteArray(0, ripRequestPacket.size()));
                }
            }
        }
    }

    public void deactivateRip() {
        for (Interface iface : activeRipIfacesList) {
            iface.setRipActivated(false);
        }
        activeRipIfacesList.clear();
        for (Iterator<RoutingTableItem> it = routingTable.getRoutingTableList().iterator(); it.hasNext();) {
            RoutingTableItem route = it.next();
            if (route.getRouteType().equals(RouteTypeEnum.DYNAMIC)) {
                it.remove();
            }
        }
    }

    public void deactivateRipOnIface(int listIndex) {
        Interface removedIface = activeRipIfacesList.remove(listIndex);
        removedIface.setRipActivated(false);
        System.out.println("removed iface " + removedIface.getIpAddress());
        //broadcast poisoned route
        for (Interface ripIface : activeRipIfacesList) {
            JMemoryPacket ripTriggeredPacket = createPacket(1, ripIface.getMacAddressBA(), ripIface.getIpAddressBA(), ripResponse);
            writeRipEntryToPacket(ripTriggeredPacket, 46, ipAfi, Utils.getNetworkAddress(removedIface.getIpAddressBA(), removedIface.getSubnetMaskBA()), removedIface.getSubnetMaskBA(), 16);
            System.out.println("sending poisoned route to from: " + ripIface.getIpAddress());
            ripIface.sendPacket(ripTriggeredPacket.getByteArray(0, ripTriggeredPacket.size()));
        }
    }

    public void sendUpdateToAllIfaces() {
        int listIndex = 0;
        List<RoutingTableItem> routesToSendList = new ArrayList<>();

        for (RoutingTableItem route : routingTable.getRoutingTableList()) {
            if (route.getRouteType().equals(RouteTypeEnum.CONNECTED) && activeRipIfacesList.contains(route.getOutputInterface())) {
                routesToSendList.add(route);
            } else if (route.getRouteType().equals(RouteTypeEnum.DYNAMIC)) {
                routesToSendList.add(route);
            }
        }
        System.out.println("entries count: " + routesToSendList.size());
        if (!routesToSendList.isEmpty()) {
            for (Interface ripActiveIface : activeRipIfacesList) {
                System.out.println("Interfejs " + activeRipIfacesList.size());
                while (listIndex < routesToSendList.size() - 1) {
                    System.out.println("List index " + listIndex);
                    send25Entries(routesToSendList, listIndex, ripActiveIface);
                    listIndex += 25;
                }
                listIndex = 0;
                /*
                 ripUpdatePacket = createPacket(entriesCount, ripActiveIface.getMacAddressBA(), ripActiveIface.getIpAddressBA(), ripResponse);
                 //fill rip entries
                 offset = 46;
                 //for (RoutingTableItem route : routingTable.getRoutingTableList()) {
                 //for (int i = 0; i < 25; i++) {
                 while (listIndex < 25) {
                 RoutingTableItem route = routingTable.getRoutingTableList().get(listIndex);
                 if (!route.getRouteType().equals(RouteTypeEnum.STATIC) && !Arrays.equals(Utils.getNetworkAddress(ripActiveIface.getIpAddressBA(), ripActiveIface.getSubnetMaskBA()), route.getNetworkAddressBA())) {
                 if (route.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
                 metric = 1;
                 } else {
                 metric = route.getActiveGateway().getMetric() + 1;
                 }
                 writeRipEntryToPacket(ripUpdatePacket, offset, ipAfi, route.getNetworkAddressBA(), route.getSubnetMaskBA(), metric);

                 offset += 20;
                 }
                 }

                 ripActiveIface.sendPacket(ripUpdatePacket.getByteArray(0, ripUpdatePacket.size()));
                 */
            }
            //a teraz budes iterovat aktivne rip interfejsy a v nich budes vytrvarat smerovaciu tabulku a vkladat do paketu vsetky 
            //zaznamy okrem statiky a tej cesty kam sa to ide posielat
        }
    }

    private void send25Entries(List<RoutingTableItem> routesToSendList, int listIndex, Interface ripActiveIface) {
        int offset, i = 0, writtenEntries = 0;
        int remainingEntries = routesToSendList.size() - listIndex;
        int entriesForSent = remainingEntries > 25 ? 25 : (remainingEntries - 1);
        long metric;
        JMemoryPacket ripUpdatePacket;
        System.out.println("remaining entries: " + remainingEntries + " entries for send: " + entriesForSent);
        ripUpdatePacket = createPacket(entriesForSent, ripActiveIface.getMacAddressBA(), ripActiveIface.getIpAddressBA(), ripResponse);
        //fill rip entries
        offset = 46;
        while (writtenEntries < entriesForSent) {
            RoutingTableItem route = routesToSendList.get(listIndex + i);
            System.out.println("WRAPING RIP ENTRY " + route.getNetworkAddress());
            if (!Arrays.equals(Utils.getNetworkAddress(ripActiveIface.getIpAddressBA(), ripActiveIface.getSubnetMaskBA()), route.getNetworkAddressBA())) { //if it is not the interface that i am sending to
                System.out.println("SOM DNU, ANO!");                
                if (route.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
                    metric = 1;
                } else {
                    metric = route.getActiveGateway().getMetric() + 1;
                }
                writeRipEntryToPacket(ripUpdatePacket, offset, ipAfi, route.getNetworkAddressBA(), route.getSubnetMaskBA(), metric);

                offset += 20;
                writtenEntries++;
            }
            i++;
        }
        System.out.println("Sending packet from " + ripActiveIface.getIpAddress());
        ripActiveIface.sendPacket(ripUpdatePacket.getByteArray(0, ripUpdatePacket.size()));
    }

    private JMemoryPacket createPacket(int entriesCount, byte[] srcMac, byte[] srcIp, int ripCommand) {
        JMemoryPacket ripUpdatePacket = new JMemoryPacket(14 + 20 + 8 + 4 + entriesCount * 20); //total packet length = ethernet header + ip header + udp header + rip header + rip entries
        //Ethernet header
        ripUpdatePacket.setByteArray(0, mcastMac); //dst        
        ripUpdatePacket.setByteArray(6, srcMac); //src        
        ripUpdatePacket.setUShort(12, 0x0800); //ethertype                
        //IP header
        ripUpdatePacket.setUByte(14, 0x40 | 0x05); //ip version, ihl
        ripUpdatePacket.setUByte(15, 0xC0); //dscp, ecn
        ripUpdatePacket.setUShort(16, 20 + 8 + 4 + entriesCount * 20); //total length = ip header + udp header + rip header + rip entries
        ripUpdatePacket.setUInt(18, 0); //identification, flags
        ripUpdatePacket.setUByte(22, 2); //ttl
        ripUpdatePacket.setUByte(23, 0x11); //udp protocol encapsuled
        ripUpdatePacket.setUShort(24, 0); //checksum set to 0

        ripUpdatePacket.setByteArray(26, srcIp); //src ip
        ripUpdatePacket.setByteArray(30, mcastIp); //dst ip

        ripUpdatePacket.setByteArray(24, Utils.RFC1071Checksum(ripUpdatePacket.getByteArray(14, 20))); //ip header checksum

        //UDP header
        ripUpdatePacket.setUShort(34, 520); //src port
        ripUpdatePacket.setUShort(36, 520); //dst port
        ripUpdatePacket.setUShort(38, 8 + 4 + entriesCount * 20); //length = udp header + rip header + rip entries
        ripUpdatePacket.setUShort(40, 0); //null checksum

        //RIP header
        ripUpdatePacket.setUByte(42, ripCommand); //command .. 1 = request, 2 = response
        ripUpdatePacket.setUByte(43, 2); //version
        ripUpdatePacket.setUShort(44, 0); //all zeros

        return ripUpdatePacket;
    }

    private void writeRipEntryToPacket(JMemoryPacket ripPacket, int offset, int afi, byte[] ipAddress, byte[] subnetMask, long metric) {
        ripPacket.setUShort(offset, afi); //AFI
        ripPacket.setUShort(offset + 2, 0); //Route tag
        ripPacket.setByteArray(offset + 4, ipAddress); //ip address
        ripPacket.setByteArray(offset + 8, subnetMask); // subnet mask
        ripPacket.setUInt(offset + 16, metric);
    }

    /*
     private void createAndSendRipPacket(Interface ripIface, int entriesCount) {
     JMemoryPacket ripUpdatePacket = new JMemoryPacket(46 + entriesCount * 20);
     //ripUpdatePacket.order(ByteOrder.BIG_ENDIAN);   
     //Ethernet header
     ripUpdatePacket.setByteArray(0, mcastMac); //dst        
     ripUpdatePacket.setByteArray(6, ripIface.getMacAddressBA()); //src        
     ripUpdatePacket.setUShort(12, 0x0800); //ethertype                
     //IP header
     ripUpdatePacket.setUByte(14, 0x40 | 0x05); //ip version, ihl
     ripUpdatePacket.setUByte(15, 0xC0); //dscp, ecn
     ripUpdatePacket.setUShort(16, 20 + 8 + 4 + entriesCount * 20); //total length = ip header + udp header + rip header + rip entries
     ripUpdatePacket.setUInt(18, 0); //identification, flags
     ripUpdatePacket.setUByte(22, 2); //ttl
     ripUpdatePacket.setUByte(23, 0x11); //udp protocol encapsuled
     ripUpdatePacket.setUShort(24, 0); //checksum set to 0

     ripUpdatePacket.setByteArray(26, ripIface.getIpAddressBA()); //src ip
     ripUpdatePacket.setByteArray(30, mcastIp); //dst ip

     ripUpdatePacket.setByteArray(24, Utils.RFC1071Checksum(ripUpdatePacket.getByteArray(14, 20))); //ip header checksum

     //UDP header
     ripUpdatePacket.setUShort(34, 520); //src port
     ripUpdatePacket.setUShort(36, 520); //dst port
     ripUpdatePacket.setUShort(38, 8 + 4 + entriesCount * 20); //length = udp header + rip header + rip entries
     ripUpdatePacket.setUShort(40, 0); //null checksum
     //RIP header
     ripUpdatePacket.setUByte(42, 2); //command
     ripUpdatePacket.setUByte(43, 2); //version
     ripUpdatePacket.setUShort(44, 0); //all zeros

     System.out.println("RIP update sent to: " + ripIface.getName() + " (" + ripIface.getIpAddress() + ") entries: " + entriesCount);
     //RIP entries
     int offset = 46, i = 1;
     for (RoutingTableItem route : routingTable.getRoutingTableList()) {
     if (!route.getRouteType().equals(RouteTypeEnum.STATIC) && !Arrays.equals(Utils.getNetworkAddress(ripIface.getIpAddressBA(), ripIface.getSubnetMaskBA()), route.getNetworkAddressBA())) {
     ripUpdatePacket.setUShort(offset, 2); //AFI
     ripUpdatePacket.setUShort(offset + 2, 0); //Route tag
     ripUpdatePacket.setByteArray(offset + 4, route.getNetworkAddressBA()); //ip address
     ripUpdatePacket.setByteArray(offset + 8, route.getSubnetMaskBA()); // subnet mask
     System.out.print("network address: " + Utils.ipByteArrayToString(route.getNetworkAddressBA()) + "  ");
     ripUpdatePacket.setUInt(offset + 12, 0); //gateway
     if (route.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
     //ripUpdatePacket.setUInt(offset + 12, 0); //gateway
     ripUpdatePacket.setUInt(offset + 16, 1); //metric
     System.out.println(i + ": 0.0.0.0");
     } else {
     //ripUpdatePacket.setByteArray(offset + 12, route.getActiveGateway().getIpAddress()); //gateway, next hop
     ripUpdatePacket.setUInt(offset + 16, route.getActiveGateway().getMetric() + 1); //metric
     int metric = route.getActiveGateway().getMetric() + 1;
     System.out.println(i + ": " + Utils.ipByteArrayToString(route.getActiveGateway().getIpAddress()) + " (" + metric + ") ");
     }
     offset += 20;

     i++;
     }
     }

     ripIface.sendPacket(ripUpdatePacket.getByteArray(0, ripUpdatePacket.size()));
     }
     */
    public List<Interface> getActiveRipIfacesList() {
        return activeRipIfacesList;
    }

    public RoutingTable getRoutingTable() {
        return routingTable;
    }

}
