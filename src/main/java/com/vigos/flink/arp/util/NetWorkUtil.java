package com.vigos.flink.arp.util;

import com.alibaba.fastjson.JSON;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

/**
 * Created by duke on 2016/11/16.
 * arp-client
 */
public class NetWorkUtil {
    private static Logger logger = LoggerFactory.getLogger(NetWorkUtil.class);

    public static byte[] stomac(String s) {
        byte[] mac = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        String[] s1 = s.split("-");
        for (int x = 0; x < s1.length; x++) {
            mac[x] = (byte) ((Integer.parseInt(s1[x], 16)) & 0xff);
        }
        return mac;
    }

    public static String stomac(byte[] mac) {
        String value = "";
        for (int i = 0; i < mac.length; i++) {
            String sTemp = Integer.toHexString(0xFF & mac[i]);
            value = value + sTemp + "-";
        }
        return value.substring(0, value.lastIndexOf("-"));
    }

    public static NetworkInterface getDevice(String network) throws UnsupportedEncodingException {
        while (true) {
            NetworkInterface[] devices = JpcapCaptor.getDeviceList();
            if (devices != null && devices.length > 0) {
                for (int i = 0; i < devices.length; i++) {
                    NetworkInterface networkInterface = devices[i];
                    NetworkInterfaceAddress mac = networkInterface.addresses[0];
                    NetworkInterfaceAddress device = networkInterface.addresses[1];
                    if (device.address.getHostAddress().equals(network)) {
                        logger.info("find device for ip:[{}],mac:[{}],detail:[{}]....\n" +
                                        "\t\t\t\t\tdetail info:{}",
                                network, mac.address.getHostAddress(), JSON.toJSONString(device), JSON.toJSONString(networkInterface));
                        return devices[i];
                    }
                }
            }
        }
    }
}
