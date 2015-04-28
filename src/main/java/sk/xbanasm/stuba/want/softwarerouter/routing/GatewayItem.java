
package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.util.Date;

/**
 *
 * @author Martin Banas
 */
public class GatewayItem {
    
    private byte[] ipAddress;
    private boolean active = true;
    private Long metric;
    private Date lastUpdate;

    public GatewayItem(byte[] ipAddress, long metric) {
        this.ipAddress = ipAddress;
        this.metric = metric;
    }

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public Long getMetric() {
        return metric;
    }

    public void setMetric(Long metric) {
        this.metric = metric;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
    
}
