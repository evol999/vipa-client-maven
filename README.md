VIPA TCP Client Maven Project
=============================

This project implements a VIPA TCP *client* that connects to a VIPA terminal (which acts as server).
It demonstrates:
 - building and sending Start Transaction [DE, D1]
 - parsing incoming VIPA frames
 - building and sending Continue Transaction [DE, D2] for multiple scenarios:
   DECLINE, APPROVE_OFFLINE (default), APPROVE_ONLINE, MINIMAL

Build:
  mvn package

Run:
  java -jar target/vipa-client-1.0-SNAPSHOT-jar-with-dependencies.jar <vipaHost> <vipaPort> [DECISION]

Example:
  java -jar target/vipa-client-1.0-SNAPSHOT-jar-with-dependencies.jar 192.168.1.50 16107 APPROVE_OFFLINE

If DECISION omitted, APPROVE_OFFLINE is used.

