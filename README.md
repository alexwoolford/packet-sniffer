# packet-sniffer

I was recently asked about a scenario where multicast network packets are used to broadcast status messages for a specific process.

I wrote this quick & dirty packet sniffer that captures multicast messages, extracts the source/destination IP's, and payload (as base64). These messages are written as JSON to a Kafka topic. Here's a sample message:

    {
        "src": "10.0.1.55",
        "payload": "TS1TRUFSQ0ggKiBIVFRQLzEuMQ0KTVg6IDQNCk1BTjogInNzZHA6ZGlzY292ZXIiDQpIT1NUOjIzOS4yNTUuMjU1LjI1MDoxOTAwDQpTVDogdXJuOnNjaGVtYXMtdXBucC1vcmc6ZGV2aWNlOlpvbmVQbGF5ZXI6MQ0KDQo=",
        "dest": "239.255.255.250",
        "timestamp": 1545979971695
    }

A StreamSets Data Collector pipeline will be used to implement the downstream logic, i.e. to parse, aggregate, and alert on those messages. 
