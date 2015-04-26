package sk.xbanasm.stuba.want.softwarerouter.forwarding;

import sk.xbanasm.stuba.want.softwarerouter.routing.RoutingTable;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.protocol.network.Ip4;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;
import sk.xbanasm.stuba.want.softwarerouter.packetanalyzer.ReceivedPacket;

/**
 *
 * @author Martin Banas
 */
public class Forwarder implements Runnable {

    private final Queue<ReceivedPacket> receivedPacketsQueue;
    private Queue<ReceivedPacket> receivedArpPacketsQueue;
    private ReceivedPacket packet;
    private final List<Interface> ports;
    private RoutingTable routingTable;

    private ArpTable arpTable;

    public Forwarder(List<Interface> connectedPorts, Queue<ReceivedPacket> receivedPacketsQueue, Queue<ReceivedPacket> receivedArpPacketsQueue, RoutingTable routingTable) {
        this.arpTable = new ArpTable(receivedArpPacketsQueue);
        this.receivedPacketsQueue = receivedPacketsQueue;
        this.receivedArpPacketsQueue = receivedArpPacketsQueue;
        this.ports = connectedPorts;
        this.routingTable = routingTable;
        new Thread(arpTable).start();
    }

    @Override
    public void run() {
        while (true) {
            while (!receivedPacketsQueue.isEmpty()) {
                packet = receivedPacketsQueue.poll();

                if (packet.isIpv4Found()) {
                    /*
                     if (Arrays.equals(packet.getIpv4Header().getDstIpBA(), packet.getSourceInterface().getIpAddressBA())) {
                     if (packet.getIpv4Header().isIcmpFound() && packet.getIpv4Header().getIcmpHeader().getIcmpMessage().equals("Echo Request")) {
                     try {
                     //ICMP REPLY
                     byte[] dstMac = arpTable.getDestMacAddress(packet.getIpv4Header().getSrcIpBA(), packet.getSourceInterface());
                     if (dstMac != null) {
                     packet.getPacket().setByteArray(0, dstMac);
                     packet.getPacket().setByteArray(6, packet.getSourceInterface().getMacAddressBA());
                     createIcmpReply(packet);

                     }
                     } catch (UnknownHostException ex) {
                     Logger.getLogger(Forwarder.class.getName()).log(Level.SEVERE, null, ex);
                     }
                     }
                     } else {*/
                    //if (!packet.getIpv4Header().getDstIp().equals("192.168.1.255") && !packet.getIpv4Header().getDstIp().equals("192.168.2.255")) {
                    try {
                        //System.out.println("dest ip: " + packet.getIpv4Header().getDstIp());                        
                        byte[] forwardingIfaceIp = routingTable.getRoute(packet, packet.getIpv4Header().getDstIpBA());                        
                        if (forwardingIfaceIp != null) {
                            System.out.println("forwarding iface: " + packet.getOutputInterface().getName() + "  ip: " + Utils.ipByteArrayToString(forwardingIfaceIp));
                            //nasla sa cesta pre tento paket -> nastavil sa mu cielovy interfejs
                            //a cielova MAC sa bude hladat na zaklade vratenej forwarding interface ip
                            byte[] dstMac = arpTable.getDestMacAddress(forwardingIfaceIp, packet.getOutputInterface());
                            if (dstMac != null) {
                                packet.getPacket().setByteArray(0, dstMac);
                                packet.getPacket().setByteArray(6, packet.getOutputInterface().getMacAddressBA());

                                if (packet.isForRouter() && packet.getIpv4Header().isIcmpFound() && packet.getIpv4Header().getIcmpHeader().getIcmpMessage().equals("Echo Request")) {
                                    createIcmpReply(packet);
                                } else {
                                    decreaseTTL(packet);
                                }
                                packet.getOutputInterface().sendPacket(packet.getPacketByteArray());
                            }
                        }
                    } catch (UnknownHostException ex) {
                        Logger.getLogger(Forwarder.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

               // }
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(Forwarder.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
    }

    private void createIcmpReply(ReceivedPacket packet) {
        //IP header        
        packet.getPacket().setByteArray(26, packet.getIpv4Header().getDstIpBA());
        packet.getPacket().setByteArray(30, packet.getIpv4Header().getSrcIpBA());
        decreaseTTL(packet);
        //ICMP header
        packet.getPacket().setByteArray(34 + packet.getIpv4Header().getIpHeaderOptionsLen(), new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0});
        packet.getPacket().setByteArray(36 + packet.getIpv4Header().getIpHeaderOptionsLen(), Utils.RFC1071Checksum(packet.getPacket().getByteArray(34 + packet.getIpv4Header().getIpHeaderOptionsLen(), packet.getPacket().size() - 34)));
        //packet.getSourceInterface().sendPacket(packet.getPacketByteArray());
    }

    private void calculateIpHeaderChecksum(ReceivedPacket packet) {
        packet.getPacket().setByte(24, (byte) 0);
        packet.getPacket().setByte(25, (byte) 0);
        Ip4 ip = packet.getPacket().getHeader(new Ip4());
        ip.checksum(ip.calculateChecksum());        
        //packet.getPacket().setByteArray(24, Utils.RFC1071Checksum(packet.getPacket().getByteArray(14, 20 + packet.getIpv4Header().getIpHeaderOptionsLen())));
    }

    private void decreaseTTL(ReceivedPacket packet) {
        int ttl = (int) packet.getPacket().getByte(22) & 0xFF;
        packet.getPacket().setByte(22, (byte) --ttl);
        calculateIpHeaderChecksum(packet);
    }

    public ArpTable getArpTable() {
        return arpTable;
    }

}
