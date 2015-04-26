
package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.util.Date;

/**
 *
 * @author Martin Banas
 */
public class GatewayItem {
    
    private byte[] ipAddress;
    private boolean active = true;
    private Integer metric;
    private Date lastUpdate;

    public GatewayItem(byte[] ipAddress, Integer metric) {
        this.ipAddress = ipAddress;
        this.metric = metric;
    }

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public Integer getMetric() {
        return metric;
    }

    public void setMetric(Integer metric) {
        this.metric = metric;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
    
}
