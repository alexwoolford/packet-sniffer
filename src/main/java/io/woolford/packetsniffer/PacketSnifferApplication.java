package io.woolford.packetsniffer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableAutoConfiguration
@ComponentScan
@EnableScheduling
public class PacketSnifferApplication {

    public static void main(String[] args) {
        SpringApplication.run(PacketSnifferApplication.class, args);
    }
}
