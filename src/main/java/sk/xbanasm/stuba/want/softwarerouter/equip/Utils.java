/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.xbanasm.stuba.want.softwarerouter.equip;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 *
 * @author Martin Banas
 */
public class Utils {

    public static String macByteArrayToHexString(byte[] a) {
        int i;
        if (a == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (i = 0; i < (a.length - 1); i++) {
            sb.append(String.format("%02X:", a[i] & 0xff));
        }
        sb.append(String.format("%02X", a[i] & 0xff));

        return sb.toString();
    }

    public static String ipByteArrayToString(byte[] a) {
        int i;
        StringBuilder sb = new StringBuilder();
        for (i = 0; i < (a.length - 1); i++) {
            sb.append(String.format("%d.", a[i] & 0xff));
        }
        sb.append(String.format("%d", a[i] & 0xff));

        return sb.toString();
        /*
         InetAddress ip = InetAddress.getByAddress(a);
         return ip.getHostAddress();
         */
    }

    public static int byteArrayToInt(byte[] byteNum) {
        return ByteBuffer.wrap(byteNum).getInt();
        //return byteNum[0] << 24 | (byteNum[1] & 0xFF) << 16 | (byteNum[2] & 0xFF) << 8 | (byteNum[3] & 0xFF);
    }

    public static byte[] ipAddressToByteArray(String ipAddress) throws UnknownHostException {
        InetAddress ip = InetAddress.getByName(ipAddress);
        return ip.getAddress();
    }

    public static String getDataFromExternFile(Integer searchNumber, String fileName) throws FileNotFoundException, IOException {
        File f = new File("F:/VI.semester/WAN/zadanie/Maven project/SoftwareRouter/src/main/resources/externFiles/" + fileName + ".txt");
        try (InputStream servicesStream = new FileInputStream(f)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(servicesStream));
            String line;
            String[] lineContent;
            Integer serviceNumber;

            while ((line = reader.readLine()) != null) {
                lineContent = line.split("   ");

                serviceNumber = Integer.parseInt(lineContent[0].substring(2), 16);
                if (searchNumber.equals(serviceNumber)) {
                    return lineContent[1];
                }
            }
        }
        return "";
    }

    public static boolean isIntegerValue(String text) {
        try {
            Integer.parseInt(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static byte[] RFC1071Checksum(byte[] buffer) {
        int i = 0, value;
        long sum = 0;
        byte[] data = new byte[2];
        int length = buffer.length;
        while (length > 0) {
            sum += (buffer[i++] & 0xff) << 8;
            if ((--length) == 0) {
                break;
            }
            sum += (buffer[i++] & 0xff);
            --length;
        }
        value = (int) (~((sum & 0xFFFF) + (sum >> 16))) & 0xFFFF;

        data[0] = (byte) ((value & 0xffffffff) >> 8);
        data[1] = (byte) (value & 0xffffffff);
        return data;
    }

    public static byte[] getNetworkAddress(byte[] ipAddress, byte[] subnetMask) {
        byte[] na = new byte[ipAddress.length];
        for (int i = 0; i < ipAddress.length; i++) {
            na[i] = (byte) (ipAddress[i] & subnetMask[i]);
        }
        return na;
    }

    public static Long ipToLong(byte[] ipAddress) {
        long result = 0;

        for (int i = 3; i >= 0; i--) {
            //long ip = Long.parseLong(ipAddressInArray[3 - i]);
            result |= ipAddress[3 - i] << (i * 8);
        }
        return result;
    }
}
