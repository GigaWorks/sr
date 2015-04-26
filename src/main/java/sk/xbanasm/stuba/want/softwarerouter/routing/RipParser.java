package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.math.BigInteger;
import java.net.UnknownHostException;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
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
public class RipParser implements Runnable {

    private boolean activeRipRouting = false;
    private Queue<ReceivedPacket> receivedRipPacketsQueue;
    private RoutingTable routingTable;
    private ReceivedPacket ripPacket;

    private List<Interface> activeRipIfacesList = new ArrayList<>();
    List<Interface> connectedPorts;
    private Date lastUpdateSent = new Date();

    private byte[] mcastMac = {(byte) 0x01, (byte) 0x00, (byte) 0x5e, (byte) 0x00, (byte) 0x00, (byte) 0x09}; //01:00:5e:00:00:09
    private byte[] mcastIp = {(byte) 0xE0, (byte) 0x00, (byte) 0x00, (byte) 0x09}; //224.0.0.9

    public RipParser(List<Interface> connectedPorts,Queue<ReceivedPacket> receivedRipPacketsQueue, RoutingTable routingTable) {
        this.connectedPorts = connectedPorts;
        this.receivedRipPacketsQueue = receivedRipPacketsQueue;
        this.routingTable = routingTable;
    }

    @Override
    public void run() {
        Date actualDate;
        while (true) {
            while (!receivedRipPacketsQueue.isEmpty()) {
                ripPacket = receivedRipPacketsQueue.poll();
                System.out.println("Dosral som rip paketlik " + !ripPacket.getIpv4Header().getTcpUdpAnalyser().isRequest());
                if (!ripPacket.getIpv4Header().getTcpUdpAnalyser().isRequest()) {
                    parseReceivedNeighborRoutes();
                }

                actualDate = new Date();
                if (actualDate.getTime() - lastUpdateSent.getTime() > 30000) {
                    sendUpdate();
                }

            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(RipParser.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void activateRipOnIface(byte[] network) {
        for (RoutingTableItem item : routingTable.getRoutingTableList()) {
            if (item.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
                if (Arrays.equals(item.getNetworkAddressBA(), network)) {
                    item.getOutputInterface().setRipActivated(true);
                    activeRipIfacesList.add(item.getOutputInterface());
                }
            }
        }
        sendUpdate();
    }

    public void deactivateRip() {
        for (Interface iface : activeRipIfacesList) {
            iface.setRipActivated(false);
        }
        activeRipIfacesList.clear();
    }

    private void parseReceivedNeighborRoutes() {
        int entriesCount = ripPacket.getIpv4Header().getTcpUdpAnalyser().getEntriesCount();
        int entriesOffset = ripPacket.getIpv4Header().getTcpUdpAnalyser().getEntriesOffset();

        System.out.println("RIP od: " + ripPacket.getIpv4Header().getSrcIp() + "  pocet zaznamov: " + entriesCount);
        for (int i = 0; i < entriesCount; i++) {
            if ((ripPacket.getPacket().getByte(entriesOffset + 1) & 0xFF) == 2) {
                try {
                    byte[] gateway;
                    if (Arrays.equals(ripPacket.getPacket().getByteArray(entriesOffset + 12, 4), Utils.ipAddressToByteArray("0.0.0.0"))) {
                        gateway = ripPacket.getIpv4Header().getSrcIpBA();
                    } else {
                        gateway = ripPacket.getPacket().getByteArray(entriesOffset + 12, 4);
                    }

                    byte[] network = ripPacket.getPacket().getByteArray(entriesOffset + 4, 4);
                    int metric = new BigInteger(ripPacket.getPacket().getByteArray(entriesOffset + 16, 4)).intValue();

                    System.out.println("siet: " + Utils.ipByteArrayToString(network) + "  metrika: " + metric);
                    //System.out.println("ip: " + Utils.ipByteArrayToString(ripPacket.getPacket().getByteArray(entriesOffset + 4, 4)) + "  mask: " + Utils.ipByteArrayToString(ripPacket.getPacket().getByteArray(entriesOffset + 8, 4)) + "  gateway: " + Utils.ipByteArrayToString(gateway) + "  metric: " + new BigInteger(ripPacket.getPacket().getByteArray(entriesOffset + 16, 4)).intValue());
                    routingTable.addRoute(RouteTypeEnum.DYNAMIC, network, ripPacket.getPacket().getByteArray(entriesOffset + 8, 4), null, new GatewayItem(gateway, metric));
                } //ripPacket.getPacket().getByteArray(index, size);
                catch (UnknownHostException ex) {
                    Logger.getLogger(RipParser.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            entriesOffset += 20;
        }
    }

    private void sendUpdate() {
        int entriesCount = -1; //-1 because router dont send rip entry that routes to the broadcasted rip router

        for (RoutingTableItem route : routingTable.getRoutingTableList()) {
            if (!route.getRouteType().equals(RouteTypeEnum.STATIC)) {
                entriesCount++;
            }
        }
        if (0 < entriesCount && entriesCount <= 25) {
            for (Interface ripActiveIface : activeRipIfacesList) {                
                sendUpdatePacket(ripActiveIface, entriesCount);
            }
            this.lastUpdateSent = new Date();
            //a teraz budes iterovat aktivne rip interfejsy a v nich budes vytrvarat smerovaciu tabulku a vkladat do paketu vsetky 
            //zaznamy okrem statiky a tej cesty kam sa to ide posielat
        
        } else if (25 < entriesCount) {
            //to nakuskujes tie entriesCount
            this.lastUpdateSent = new Date();
        }             
    }

    private void sendUpdatePacket(Interface ripIface, int entriesCount) {
        JMemoryPacket ripUpdatePacket = new JMemoryPacket(46 + entriesCount * 20); //46+4 pre fcs
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
        
        System.out.println("RIP update sent to: " + ripIface.getName()+ " (" + ripIface.getIpAddress() + ") entries: " + entriesCount);
        //RIP entries
        int offset = 46, i = 1;
        for (RoutingTableItem route : routingTable.getRoutingTableList()) {
            if (!route.getRouteType().equals(RouteTypeEnum.STATIC) && !Arrays.equals(Utils.getNetworkAddress(ripIface.getIpAddressBA(), ripIface .getSubnetMaskBA()), route.getNetworkAddressBA())) {                
                ripUpdatePacket.setUShort(offset, 2); //AFI
                ripUpdatePacket.setUShort(offset + 2, 0); //Route tag
                ripUpdatePacket.setByteArray(offset + 4, route.getNetworkAddressBA()); //ip address
                ripUpdatePacket.setByteArray(offset + 8, route.getSubnetMaskBA()); // subnet mask
                if (route.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
                    ripUpdatePacket.setUInt(offset + 12, 0); //gateway
                    ripUpdatePacket.setUInt(offset + 16, 1); //metric
                    System.out.println(i + ": 0.0.0.0");
                } else {
                    ripUpdatePacket.setByteArray(offset + 12, route.getActiveGateway().getIpAddress()); //gateway, next hop
                    ripUpdatePacket.setUInt(offset + 16, route.getActiveGateway().getMetric() + 1); //metric
                    
                    System.out.println(i + ": " + Utils.ipByteArrayToString(route.getActiveGateway().getIpAddress()) + " (" + (route.getActiveGateway().getMetric() + 1) + ") ");
                }
                offset += 20;
                
                i++;
            }
        }
        
        
        ripIface.sendPacket(ripUpdatePacket.getByteArray(0, ripUpdatePacket.size()));        
    }

    public List<Interface> getActiveRipIfacesList() {
        return activeRipIfacesList;
    }

}
