/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package sk.xbanasm.stuba.want.softwarerouter.machine;

import java.io.IOException;
import org.jnetpcap.PcapIf;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;

/**
 *
 * @author Martin Banas
 */
public abstract class InterfaceAbstract {
    
    private final String portName;
    protected final PcapIf device; 
    private final String deviceName;
    private final String deviceDescription;
    private final byte[] macAddressBA;
    private String macAddress;
    
    public InterfaceAbstract(String name, PcapIf device) throws IOException {
        this.portName = name;
        this.device = device;
        this.deviceName = device.getName();
        this.deviceDescription = device.getDescription();
        this.macAddressBA = device.getHardwareAddress();
        this.macAddress = Utils.macByteArrayToHexString(macAddressBA);
    }

    public String getName() {
        return portName;
    }
    
    public PcapIf getDevice() {
        return device;
    }

    public String getDeviceName() {
        return deviceName;
    }            
    
    public String getDeviceDescription() {
        return deviceDescription;
    }

    public byte[] getMacAddressBA() {
        return macAddressBA;
    }

    public String getMacAddress() {
        return macAddress;
    }
    
}
