package sk.xbanasm.stuba.want.softwarerouter.machine;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Date;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import sk.xbanasm.stuba.want.softwarerouter.routing.RoutingTable;
import sk.xbanasm.stuba.want.softwarerouter.routing.RouteTypeEnum;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.packetanalyzer.ReceivedPacket;

/**
 *
 * @author Martin Banas
 */
public class Interface extends InterfaceAbstract implements Runnable {

    private String status = "Down";

    private byte[] ipAddressBA;
    private String ipAddress = "";
    private byte[] subnetMaskBA;
    private String subnetMask = "";

    private Interface thisInterface = this;
    private Thread portThread;
    private Queue<ReceivedPacket> receivedPacketsQueue;
    private Queue<ReceivedPacket> receivedArpPacketsQueue;
    private Queue<ReceivedPacket> receivedRipPacketsQueue;
    private RoutingTable routingTable;

    private Pcap pcap;
    private final int snaplen = 64 * 1024;           // Capture all packets, no trucation  
    private final int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    private final int timeout = 5;           // 10 seconds in millis
    private final StringBuilder errbuf = new StringBuilder();

    private boolean ripActivated = false;
    private Date lastRipUpdate = null;

    public Interface(String name, PcapIf device, Queue<ReceivedPacket> receivedPacketsQueue, Queue<ReceivedPacket> receivedArpPacketsQueue, Queue<ReceivedPacket> receivedRipPacketsQueue, RoutingTable routingTable) throws IOException {
        super(name, device);
        this.receivedPacketsQueue = receivedPacketsQueue;
        this.receivedArpPacketsQueue = receivedArpPacketsQueue;
        this.receivedRipPacketsQueue = receivedRipPacketsQueue;
        this.routingTable = routingTable;
    }

    @Override
    public void run() {
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            ReceivedPacket receivedPacket;

            @Override
            public void nextPacket(PcapPacket packet, String user) {
                if (status.equals("Up")) {
                    if (!Arrays.equals(thisInterface.getMacAddressBA(), packet.getByteArray(6, 6))) {
                        try {
                            receivedPacket = new ReceivedPacket(thisInterface, packet);
                            System.out.println("\n[Prisiel paketlik] na interface: " + thisInterface.getName() + "  od: " + receivedPacket.getSrcMac());
                        } catch (IOException ex) {
                            Logger.getLogger(Interface.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        if (receivedPacket.isArpFound() && Arrays.equals(receivedPacket.getArpHeader().getTargetProtAddrBA(), ipAddressBA)) {
                            System.out.println("Som arp " + Arrays.equals(receivedPacket.getArpHeader().getTargetProtAddrBA(), ipAddressBA));
                            receivedArpPacketsQueue.add(receivedPacket);
                        } else if (receivedPacket.isIpv4Found()) {
                            System.out.println("Som NEENI arp  " + ripActivated + " " + receivedPacket.getIpv4Header().isTransportProtocolFound());
                            // System.out.println("src ip: " + receivedPacket.getIpv4Header().getSrcIp() + "  dst ip: " + receivedPacket.getIpv4Header().getDstIp() + "  " + ripActivated + " " + receivedPacket.getIpv4Header().isTransportProtocolFound() + " " + receivedPacket.getIpv4Header().getTcpUdpAnalyser().isRipFound());
                            if (receivedPacket.getIpv4Header().isTransportProtocolFound() && receivedPacket.getIpv4Header().getTcpUdpAnalyser().isRipFound()) {
                                System.out.println("vosiel som dnu");
                                if (ripActivated) {
                                    System.out.println("RIPko som");
                                    receivedRipPacketsQueue.add(receivedPacket);
                                }
                            } else {
                                System.out.println("som nejaky stock");
                                receivedPacketsQueue.add(receivedPacket);
                            }
                        }
                    }
                }
            }
        };

        while (true) {
            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
        }
    }

    public void noShutdown(String ipAddress, String subnetMask) throws UnknownHostException {
        if (pcap == null) {
            pcap = Pcap.openLive(this.getDeviceName(), snaplen, flags, timeout, errbuf);
            if (pcap == null) {
                System.err.printf("Error while opening device for capture: " + errbuf.toString());
                return;
            }

            portThread = new Thread(this);
            portThread.start();
        }

        this.ipAddress = ipAddress;
        this.ipAddressBA = Utils.ipAddressToByteArray(ipAddress);
        this.subnetMask = subnetMask;
        this.subnetMaskBA = Utils.ipAddressToByteArray(subnetMask);

        routingTable.addRoute(RouteTypeEnum.CONNECTED, ipAddressBA, subnetMaskBA, this, null);
        status = "Up";
    }

    public void shutdown() {
        status = "Down";
        routingTable.removeConnectedRoute(this);
    }

    public void sendPacket(byte[] packet) {
        if (this.status.equals("Up")) {
            pcap.sendPacket(packet);
        }
    }

    public void setRipActivated(boolean ripActivated) {
        this.ripActivated = ripActivated;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public byte[] getIpAddressBA() {
        return ipAddressBA;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public byte[] getSubnetMaskBA() {
        return subnetMaskBA;
    }

    public String getSubnetMask() {
        return subnetMask;
    }

    public void setLastRipUpdate(Date lastRipUpdate) {
        this.lastRipUpdate = lastRipUpdate;
    }

    public Date getLastRipUpdate() {
        return lastRipUpdate;
    }
}
