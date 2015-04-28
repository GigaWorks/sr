package sk.xbanasm.stuba.want.softwarerouter.routing;

import org.jnetpcap.packet.PcapPacket;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;

/**
 *
 * @author Martin Banas
 */
public class RipEntry {

    private int afi;
    private int routeTag;
    private byte[] ipAddress;
    private byte[] subnetMask;
    private byte[] nextHop;
    private long metric;

    public RipEntry(PcapPacket packet, int offset) {
        afi = packet.getUShort(offset);
        routeTag = packet.getUShort(offset + 2);
        ipAddress = packet.getByteArray(offset + 4, 4);
        subnetMask = packet.getByteArray(offset + 8, 4);
        nextHop = packet.getByteArray(offset + 12, 4);
        metric = packet.getUInt(offset + 16);

        System.out.println("siet: " + Utils.ipByteArrayToString(ipAddress) + "  metrika: " + metric);
    }

    public int getAfi() {
        return afi;
    }

    public int getRouteTag() {
        return routeTag;
    }

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public byte[] getSubnetMask() {
        return subnetMask;
    }

    public byte[] getNextHop() {
        return nextHop;
    }

    public void setNextHop(byte[] nextHop) {
        this.nextHop = nextHop;
    }

    public long getMetric() {
        return metric;
    }

}
