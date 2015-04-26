
package sk.xbanasm.stuba.want.softwarerouter.forwarding;

import java.net.UnknownHostException;
import java.util.Date;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;

/**
 *
 * @author Martin Banas
 */
public class ArpTableItem {
    
    private byte[] ipAddressBA;
    private String ipAddress;
    private byte[] macAddressBA;
    private String macAddress;
    private Interface iface;
    private boolean resolved;
    private Date lastActivity;
    private final Object arpItemUpdateLock = new Object();
    
    
    public ArpTableItem(byte[] ipAddress, Interface iface, boolean resolved) throws UnknownHostException {
        this.ipAddressBA = ipAddress;
        this.ipAddress = Utils.ipByteArrayToString(ipAddress);
        this.iface = iface;
        this.resolved = resolved;
        lastActivity = new Date();
    }
    
    public void updateItemActivity() {
        lastActivity = new Date();        
    }

    public Date getLastActivity() {
        return lastActivity;
    }    

    public byte[] getIpAddressBA() {
        return ipAddressBA;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public byte[] getMacAddressBA() {
        return macAddressBA;
    }

    public void setMacAddress(byte[] macAddress) {
        this.lastActivity = new Date();
        this.macAddressBA = macAddress;
        this.macAddress = Utils.macByteArrayToHexString(macAddress);
        synchronized (arpItemUpdateLock) {
            arpItemUpdateLock.notifyAll();
        }
    }

    public Object getArpItemUpdateLock() {
        return arpItemUpdateLock;
    }

    public Interface getInterface() {
        return iface;
    }            

    public boolean isResolved() {
        return resolved;
    }

    public void setResolved() {
        this.resolved = true;
    }
}
