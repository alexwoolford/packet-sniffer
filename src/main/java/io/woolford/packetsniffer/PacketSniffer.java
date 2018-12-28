package io.woolford.packetsniffer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.xml.bind.DatatypeConverter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;

@Component
public class PacketSniffer {

    Logger logger = LoggerFactory.getLogger(PacketSniffer.class);

    int SNAPLEN = 65535;
    int READ_TIMEOUT = 50;
    int COUNT = 0;

    @Autowired
    private KafkaTemplate kafkaTemplate;

    @PostConstruct
    private void sniffPackets() throws UnknownHostException, PcapNativeException, NotOpenException {

        InetAddress addr = InetAddress.getLocalHost();
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

        if (nif == null) {
            return;
        }

        logger.info(nif.getName() + "(" + nif.getDescription() + ")");

        final PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        // filter for IPv4 multicast packets
        String filter = "ether multicast and ip";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        logger.info("Sniffing IPv4 multicast packets");

        PacketListener listener =
                new PacketListener() {
                    @Override
                    public void gotPacket(Packet packet) {

                        long timestamp = System.currentTimeMillis();
                        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                        Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
                        Inet4Address destAddr = ipV4Packet.getHeader().getDstAddr();
                        byte[] bytes = ipV4Packet.getPayload().getPayload().getRawData();

                        HashMap<String, Object> record = new HashMap<>();
                        record.put("timestamp", timestamp);
                        record.put("src", srcAddr.getHostAddress());
                        record.put("dest", destAddr.getHostAddress());
                        record.put("payload", DatatypeConverter.printBase64Binary(bytes));

                        ObjectMapper mapper = new ObjectMapper();
                        String json = null;

                        try {
                            json = mapper.writeValueAsString(record);
                        } catch (JsonProcessingException e) {
                            logger.error(e.getMessage());
                        }

                        logger.info(json);
                        kafkaTemplate.send("multicast", json);

                    }
                };

        try {
            handle.loop(COUNT, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        PcapStat ps = handle.getStats();
        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());

        handle.close();
    }

}
