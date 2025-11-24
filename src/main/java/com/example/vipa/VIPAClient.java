package com.example.vipa;

import java.io.*;
import java.net.Socket;
import java.util.Arrays;

/**
 * VIPA TCP Client
 *
 * Connects to a VIPA terminal (server/listening sockets) and demonstrates: -
 * Start Transaction [DE, D1] - Receiving E2/EA templates (decision required) -
 * Sending Continue Transaction [DE, D2] with selectable decision
 *
 * Usage: java -jar vipa-client.jar <vipaHost> <vipaPort> [DECISION]
 *
 * DECISION: DECLINE | APPROVE_OFFLINE | APPROVE_ONLINE | MINIMAL
 */
public class VIPAClient {

	private final String host;
	private final int port;
	private final ContinueDecision decision;

	public VIPAClient(String host, int port, ContinueDecision decision) {
		this.host = host;
		this.port = port;
		this.decision = decision;
	}

	public void run() {
		try (Socket socket = new Socket(host, port)) {
			System.out.println("<< 1. Connected to VIPA terminal " + host + ":" + port);
			InputStream in = socket.getInputStream();
			OutputStream out = socket.getOutputStream();
			byte[] commandTx;

			readVipaAnswer(in, out);

			// Send display Text
//			commandTx = buildDisplayInsertCard("Welcome");
//			System.out.println("<< Welcome " + bytesToHex(commandTx));
//			writeVipaCommand(out, commandTx);
			
			//readVipaAnswer(in, out);

			// Send display Insert Card
			commandTx = buildDisplayInsertCard();
			System.out.println("<< 2. Sending Display Card: " + bytesToHex(commandTx));
			writeVipaCommand(out, commandTx);

			readVipaAnswer(in, out);

			// Enable card detection
			commandTx = buildEnableCardStatus();
			System.out.println("<< 3. Sending Enable Card Detection: " + bytesToHex(commandTx));
			writeVipaCommand(out, commandTx);

			readVipaAnswer(in, out);

			try {
				waitForUser(in, "card inserted");
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			// Send Start Transaction example
			commandTx = buildStartTransactionExample();
			System.out.println("<< 4. Sending Start Transaction: " + bytesToHex(commandTx));
			writeVipaCommand(out, commandTx);

			readVipaAnswer(in, out);

			try {
				waitForUser(in, "Terminal responded");
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			readVipaAnswer(in, out);

			// Continue Transaction
			commandTx = buildContinueTransaction(decision, null);
			System.out.println("<< 5. Continue Transaction: " + bytesToHex(commandTx));
			writeVipaCommand(out, commandTx);

			while (true) {
				readVipaAnswer(in, out);
			}

		} catch (IOException e) {
			System.err.println("I/O error: " + e.getMessage());
		}
	}

	private byte[] buildDisplayInsertCard(String string) {
		// Build a Start Transaction [DE, D1] similar to spec Example 37
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		bout.write(0x01); // NAD
		bout.write(0x00); // PCB

		ByteArrayOutputStream body = new ByteArrayOutputStream();
		body.write(0xD2); // CLA
		body.write(0x02); // INS
		body.write(0x00); // P1
		body.write(0x00); // P2

		// Build E0 template
		ByteArrayOutputStream e0 = new ByteArrayOutputStream();
		// DF8104 - sample
		e0.write(0xDF);
		e0.write(0x81);
		e0.write(0x04);
		try {
			e0.write(string.getBytes());
		} catch (IOException ignored) {
		}

		// Wrap E0 with header and trailer bytes (01 00)
		byte[] e0b = e0.toByteArray();
		ByteArrayOutputStream data = new ByteArrayOutputStream();
		data.write(0xE0);
		data.write(e0b.length + 2); // plus trailer bytes
		try {
			data.write(e0b);
			data.write(0x01);
			data.write(0x00);
		} catch (IOException ignored) {
		}

		byte[] dataBytes = data.toByteArray();
		body.write((byte) dataBytes.length);
		try {
			body.write(dataBytes);
		} catch (IOException ignored) {
		}

		byte[] bodyBytes = body.toByteArray();
		// len = number of bytes AFTER LEN and BEFORE LRC
		int len = bodyBytes.length;
		bout.write((byte) len);
		try {
			bout.write(bodyBytes);
		} catch (IOException ignored) {
		}

		byte lrc = computeLRC(bout.toByteArray());
		bout.write(lrc & 0xFF);

		return bout.toByteArray();	}

	private void handleEmvResponse(byte[] frame, OutputStream out) throws IOException {
		// Extract TLV payload (from offset 3 up to last-1 (excluding LRC))
		byte[] payload = Arrays.copyOfRange(frame, 3, frame.length - 1);
		System.out.println("Parsed payload: " + bytesToHex(payload));

		// Send continue with the selected decision.
		byte[] continueTx = buildContinueTransaction(decision, payload);
		System.out.println("<< Sending Continue Transaction (" + decision + "): " + bytesToHex(continueTx));
		out.write(continueTx);
		out.flush();
	}

	// *************** VIPA frame I/O utilities ****************

	private static byte[] readVipaFrame(InputStream in) throws IOException {
		// Read NAD
		int nad = in.read();
		if (nad < 0)
			return null;
		int pcb = in.read();
		if (pcb < 0)
			return null;
		int len = in.read();
		if (len < 0)
			return null;
		byte[] rest = readExactly(in, len + 1);
		if (rest == null)
			return null;
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		bout.write(nad);
		bout.write(pcb);
		bout.write(len);
		bout.write(rest);
		return bout.toByteArray();
	}

	private static byte[] readExactly(InputStream in, int n) throws IOException {
		byte[] buf = new byte[n];
		int off = 0;
		while (off < n) {
			int r = in.read(buf, off, n - off);
			if (r < 0)
				return null;
			off += r;
		}
		return buf;
	}

	private void readVipaAnswer(InputStream in, OutputStream out) throws IOException {
		// After connecting, read unsolicited wake-up frame first
		byte[] commandRx = readVipaFrame(in);
		if (commandRx != null) {
			System.out.println(">> Received: " + bytesToHex(commandRx));
			// Minimal parsing
			if (commandRx.length >= 5) {

				int cla = commandRx[3] & 0xFF;
				int ins = commandRx[4] & 0xFF;
				if (cla == 0xE6 && ins == 0x21) {
					System.out.println("Received unsolicited Device Powered On. Ignoring.");
				} else if (cla == 0xDE && (ins == 0xD1 || ins == 0xD2 || ins == 0xE2)) {
					// EMV response / decision required
					handleEmvResponse(commandRx, out);
				} else if (cla == 0xE0 || cla == 0x90) {
					System.out.println("OK continue: ");
				} else if (cla == 0xE2 || cla == 0x90) {
					handleEmvResponse(commandRx, out);
				} else if (cla == 0xE6) {
					System.out.println("Received: " + extractC4ToC5String(commandRx));
				} else {
					System.out.println("Unexpected first frame: " + bytesToHex(commandRx));
				}
			} else {
				System.out.println("Received too-short frame: " + bytesToHex(commandRx));
			}
		} else {
			System.out.println("Connection closed by remote.");
		}
	}

	private void writeVipaCommand(OutputStream out, byte[] commandTx) throws IOException {
//		System.out.println("<< Enable Card Status: " + bytesToHex(commandTx));
		out.write(commandTx);
		out.flush();
	}

	private boolean waitForUser(InputStream in, String event) throws IOException, InterruptedException {
		boolean retVal = false;
		long startTime = System.currentTimeMillis();

		System.out.println("waiting for user");
		while (System.currentTimeMillis() - startTime < 30000) {
			System.out.print(".");
			// Check if any data is immediately available
			if (in.available() > 0) {
				retVal = true;
				System.out.println();
				System.out.println(event);
				break;
			}
			Thread.sleep(100);
		}
		return retVal;

	}

	// *************** Frame builders ****************
	private static byte[] buildEnableCardStatus() throws IOException {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		bout.write(0x01); // NAD
		bout.write(0x00); // PCB

		// D0 60 01 01
		byte[] apdu = new byte[] { (byte) 0xD0, (byte) 0x60, (byte) 0x01, (byte) 0x01 };

		bout.write(apdu.length); // LEN
		bout.write(apdu);

		// LRC
		byte lrc = 0;
		for (byte b : bout.toByteArray())
			lrc ^= b;
		bout.write(lrc);

		return bout.toByteArray();
	}

	private static byte[] buildDisplayInsertCard() throws IOException {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		// NAD, PCB
		bout.write(0x01); // NAD
		bout.write(0x00); // PCB

		// The APDU: D2 01 0D 01
		byte[] apdu = new byte[] { (byte) 0xD2, // CLA
				(byte) 0x01, // INS = Display
				(byte) 0x0D, // P1 = screen index 0x0D = Insert Card
				(byte) 0x01 // P2 = backlight ON
		};

		// LEN = APDU length
		bout.write(apdu.length);

		// Write APDU content
		bout.write(apdu);

		// Compute LRC = XOR of all bytes (except LRC itself)
		byte lrc = 0;
		for (byte b : bout.toByteArray()) {
			lrc ^= b;
		}
		bout.write(lrc);

		return bout.toByteArray();
	}

	private static byte[] buildStartTransactionExample() {
		// Build a Start Transaction [DE, D1] similar to spec Example 37
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		bout.write(0x01); // NAD
		bout.write(0x00); // PCB

		ByteArrayOutputStream body = new ByteArrayOutputStream();
		body.write(0xDE); // CLA
		body.write(0xD1); // INS
		body.write(0x00); // P1
		body.write(0x00); // P2

		// Build E0 template
		ByteArrayOutputStream e0 = new ByteArrayOutputStream();
		// 9A (date) 03 YY MM DD - sample
		e0.write(0x9A);
		e0.write(0x03);
		e0.write(0x01);
		e0.write(0x12);
		e0.write(0x25);
		// 9F21 (time) 03 HH MM SS
		e0.write(0x9F);
		e0.write(0x21);
		e0.write(0x03);
		e0.write(0x12);
		e0.write(0x30);
		e0.write(0x00);
		// 9C Transaction type
		e0.write(0x9C);
		e0.write(0x01);
		e0.write(0x00);
		// 9F02 amount (6 bytes) - example 0000000009895 -> we'll use 00000000009895 and
		// take last 6 bytes
		byte[] amt = hexStringToBytes("00000000009895");
		byte[] amt6 = Arrays.copyOfRange(amt, amt.length - 6, amt.length);
		e0.write(0x9F);
		e0.write(0x02);
		e0.write(0x06);
		try {
			e0.write(amt6);
		} catch (IOException ignored) {
		}

		// Wrap E0 with header and trailer bytes (01 00)
		byte[] e0b = e0.toByteArray();
		ByteArrayOutputStream data = new ByteArrayOutputStream();
		data.write(0xE0);
		data.write(e0b.length + 2); // plus trailer bytes
		try {
			data.write(e0b);
			data.write(0x01);
			data.write(0x00);
		} catch (IOException ignored) {
		}

		byte[] dataBytes = data.toByteArray();
		body.write((byte) dataBytes.length);
		try {
			body.write(dataBytes);
		} catch (IOException ignored) {
		}

		byte[] bodyBytes = body.toByteArray();
		// len = number of bytes AFTER LEN and BEFORE LRC
		int len = bodyBytes.length;
		bout.write((byte) len);
		try {
			bout.write(bodyBytes);
		} catch (IOException ignored) {
		}

		byte lrc = computeLRC(bout.toByteArray());
		bout.write(lrc & 0xFF);

		return bout.toByteArray();
	}

	public static byte[] buildContinueTransaction(ContinueDecision decision, byte[] incomingPayload) {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		bout.write(0x01); // NAD
		bout.write(0x00); // PCB

		ByteArrayOutputStream body = new ByteArrayOutputStream();
		body.write(0xDE); // CLA
		body.write(0xD2); // INS
		body.write(0x00); // P1
		body.write(0x00); // P2

		ByteArrayOutputStream tlvs = new ByteArrayOutputStream();

		try {
			switch (decision) {
			case DECLINE:
				// 8A Authorization response code – decline 05 00
				tlvs.write(0x8A);
				tlvs.write(0x02);
				tlvs.write(0x05);
				tlvs.write(0x00);
				break;
			case APPROVE_OFFLINE:
				tlvs.write(0x8A);
				tlvs.write(0x02);
				tlvs.write(0x30);
				tlvs.write(0x30);
				byte[] iad = hexStringToBytes("11223344556677889900");
				tlvs.write(0x91);
				tlvs.write(iad.length);
				tlvs.write(iad);
				break;
			case APPROVE_ONLINE:
				tlvs.write(0x8A);
				tlvs.write(0x02);
				tlvs.write(0x30);
				tlvs.write(0x30);
				byte[] iad2 = hexStringToBytes("8877665544332211AABB");
				tlvs.write(0x91);
				tlvs.write(iad2.length);
				tlvs.write(iad2);
				byte[] script = hexStringToBytes("860F842400000000010000000000000000");
				tlvs.write(0x71);
				tlvs.write(script.length);
				tlvs.write(script);
				break;
			case MINIMAL:
				// no TLVs
				break;
			}
		} catch (IOException ignored) {
		}

		byte[] tlvBytes = tlvs.toByteArray();
		body.write((byte) tlvBytes.length);
		try {
			body.write(tlvBytes);
		} catch (IOException ignored) {
		}

		byte[] bodyBytes = body.toByteArray();
		int len = bodyBytes.length;
		bout.write((byte) len);
		try {
			bout.write(bodyBytes);
		} catch (IOException ignored) {
		}

		byte lrc = computeLRC(bout.toByteArray());
		bout.write(lrc & 0xFF);

		return bout.toByteArray();
	}
	
    public static String extractC4ToC5String(byte[] commandRx) throws IOException {
        if (commandRx == null) {
            throw new IllegalArgumentException("Input byte array cannot be null");
        }
        
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        boolean foundC4 = false;
        boolean foundC5 = false;
        
        for (int i = 0; i < commandRx.length && !foundC5; i++) {
            byte b = commandRx[i];
            
            if (foundC4) {
                if (b == (byte) 0xC5) {
                    foundC5 = true;
                } else {
                    buffer.write(b);
                }
            } else if (b == (byte) 0xC4) {
                foundC4 = true;
            }
        }
        
        if (!foundC4) {
            throw new IOException("C4 marker not found in byte array");
        }
        
        if (!foundC5) {
            throw new IOException("C5 marker not found in byte array");
        }
        
        return buffer.toString("UTF-8");
    }

	private static byte computeLRC(byte[] bytes) {
		byte x = 0;
		for (byte b : bytes)
			x ^= b;
		return x;
	}

	private static String bytesToHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data)
			sb.append(String.format("%02X ", b));
		return sb.toString().trim();
	}

	private static byte[] hexStringToBytes(String s) {
		s = s.replaceAll("\\s+", "");
		if ((s.length() % 2) != 0)
			s = "0" + s;
		int len = s.length();
		byte[] out = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
		}
		return out;
	}

	public static void main(String[] args) {
		if (args.length < 2) {
			System.err.println("Usage: java -jar vipa-client.jar <vipaHost> <vipaPort> [DECISION]");
			System.err.println("DECISION options: DECLINE | APPROVE_OFFLINE | APPROVE_ONLINE | MINIMAL");
			System.exit(1);
		}
		String host = args[0];
		int port = Integer.parseInt(args[1]);
		ContinueDecision decision = ContinueDecision.APPROVE_OFFLINE;
		if (args.length >= 3) {
			try {
				decision = ContinueDecision.valueOf(args[2]);
			} catch (IllegalArgumentException e) {
				System.err.println("Unknown decision. Using default APPROVE_OFFLINE");
			}
		}
		VIPAClient client = new VIPAClient(host, port, decision);
		client.run();
	}
}
