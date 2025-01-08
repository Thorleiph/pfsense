package com.sm0tnt.pfsense.logs.decoders;

import java.util.ArrayList;

import org.apache.commons.lang3.StringUtils;
// import org.apache.flink.api.java.tuple.Tuple2;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.sm0tnt.addr.iptools.IPAddress;

import javaslang.Tuple2;

/*-
 * 956,,,1492971625,em6,ip-option,pass,in,4,0x0,,1,8,0,none,2,igmp,32,10.0.2.1,224.0.0.1,datalength=8
 * 8,,,1000000103,ix2,match,block,in,4,0x0,,41,51154,0,DF,47,gre,564,98.153.1.121,83.254.23.109,datalength=544
 */

/**
 * Base class for decoding rsyslog messages.
 */
public abstract class Decoder {
	private static final Logger logger = LogManager.getLogger(Decoder.class.getSimpleName());

	public abstract JsonNode decode(String value);

	public static final String TIMESTAMP = "timestamp";
	public static final String KEY = "key";
	public static final String VALUE = "value";
	public static final String OFFSET = "offset";
	public static final String PARTITION = "partition";
	public static final String TIME_STAMP = "timestamp";
	public static final String TOPIC = "topic";

	public static final int PROTOCOL_TYPE_OPTIONS = 0;
	public static final int PROTOCOL_TYPE_ICMP = 1;
	public static final int PROTOCOL_TYPE_IGMP = 2;
	public static final int PROTOCOL_TYPE_TCP = 6;
	public static final int PROTOCOL_TYPE_UDP = 17;
	public static final int PROTOCOL_TYPE_GRE = 47;
	public static final int PROTOCOL_TYPE_ESP = 50;
	public static final int PROTOCOL_TYPE_ICMPV6 = 58;
	public static final int PROTOCOL_TYPE_OSPF = 89;

	private static final int toInt(String s) {
		return toInt(s, -1);
	}

	private static final int toInt(String s, int d) {
		if (StringUtils.isBlank(s))
			return d;

		try {
			int radix = 10;
			if (s.startsWith("0x") || s.startsWith("0X")) {
				s = s.substring(2);
				radix = 16;
			}

			return Integer.parseInt(s, radix);
		} catch (NumberFormatException e) {
			return d;
		}
	}

	private static void logRemainder(String head, int idx, String[] parts) {
		StringBuffer sb = new StringBuffer();

		while (idx < parts.length) {
			if (sb.length() > 0)
				sb.append("\t");
			sb.append("'").append(parts[idx++]).append("'");
		}

		if (StringUtils.isNotBlank(sb.toString())) {
			if (StringUtils.isNotBlank(head)) {
				sb.insert(0, ": ");
				sb.insert(0, head);
			}

			logger.debug(sb.toString());
		}
	}

	/*
	 * public static JsonNode getAddressInfo(ObjectMapper mapper, String a) { try {
	 * URL url = new URL("http://localhost:8081/ip/" + a); URLConnection c =
	 * url.openConnection();
	 * 
	 * try (InputStream is = c.getInputStream()) { return mapper.readTree(is);
	 * 
	 * } } catch (IOException e) { }
	 * 
	 * return null; }
	 */
	public static Tuple2<String, Integer> splitICMPNumber(String s, int expectedDataLength) {

		String pt1 = "";
		int pt2 = -1;

		int p = s.length() - 1;
		int res;

		do {
			res = Integer.parseInt(s.substring(p));
			if (res != expectedDataLength)
				--p;
		} while (p > 0 && res != expectedDataLength);

		pt1 = s.substring(0, p);
		pt2 = res;

		return new Tuple2<>(pt1, pt2);
	}

	/**
	 * @param s The filter log message.
	 * @return the protocol stack.
	 */
	public static FilterLogStack decodeFilterlogMessage(String s) {
		if (StringUtils.isBlank(s))
			return null;

		FilterLogStack stack = new FilterLogStack();

		int ipDataLength = -1;

		String parts[] = s.split(",", -50);
		int idx = 0;

		int ruleNumber = toInt(parts[idx++]);
		int subRuleNumber = toInt(parts[idx++]);
		int anchor = toInt(parts[idx++]);
		int tracker = toInt(parts[idx++]);
		String realInterface = parts[idx++];
		String reason = parts[idx++];
		String action = parts[idx++];
		String direction = parts[idx++];
		int ipVersion = toInt(parts[idx++]);

		stack.add(new FilterLogHeader(ruleNumber, subRuleNumber, anchor, tracker, realInterface, reason, action, direction, ipVersion));

		int protocolId = -1;
		String protocolText = null;

		if (ipVersion == 4) {
			int v4TOS = toInt(parts[idx++]);
			String v4ECN = parts[idx++];
			int v4TTL = toInt(parts[idx++]);
			int v4Id = toInt(parts[idx++]);
			int v4Offset = toInt(parts[idx++]);
			String v4Flags = parts[idx++];
			protocolId = toInt(parts[idx++]);
			protocolText = parts[idx++].toLowerCase();
			int length = toInt(parts[idx++]);
			ipDataLength = length;
			IPAddress srcAddr = IPAddress.fromString(parts[idx++]);
			IPAddress dstAddr = IPAddress.fromString(parts[idx++]);

			stack.add(new FilterLogIPv4(srcAddr, dstAddr, v4TOS, v4ECN, v4TTL, v4Id, v4Offset, v4Flags, protocolId, protocolText, length));
		} else if (ipVersion == 6) {
			int v6Class = toInt(parts[idx++]);
			int v6FlowLabel = toInt(parts[idx++]);
			int v6HopLimit = toInt(parts[idx++]);
			protocolText = parts[idx++].toLowerCase();
			protocolId = toInt(parts[idx++]);
			int length = toInt(parts[idx++]);
			ipDataLength = length;
			IPAddress srcAddr = IPAddress.fromString(parts[idx++]);
			IPAddress dstAddr = IPAddress.fromString(parts[idx++]);

			stack.add(new FilterLogIPv6(srcAddr, dstAddr, v6Class, v6FlowLabel, v6HopLimit, protocolId, protocolText, length));
		} else {
			logger.debug("Other: " + s);
		}

		switch (protocolId) {
			case PROTOCOL_TYPE_ICMP: {
				int expectedDataLength = ipDataLength - 20;
				String tmpICMPType = parts[idx++];
				FilterLogICMP.ICMPType icmpType = FilterLogICMP.ICMPType.getType(tmpICMPType);

				switch (icmpType) {
					case Request: {
						int id = toInt(parts[idx++]);
						Tuple2<String, Integer> t2 = splitICMPNumber(parts[idx++], expectedDataLength);
						int sequence = toInt(t2._1);
						int length = t2._2;

						stack.add(new FilterLogICMP(icmpType, id, sequence, length));

						break;
					}

					case Reply: {
						int id = toInt(parts[idx++]);
						Tuple2<String, Integer> t2 = splitICMPNumber(parts[idx++], expectedDataLength);
						int sequence = toInt(t2._1);
						int length = t2._2;

						stack.add(new FilterLogICMP(icmpType, id, sequence, length));

						break;
					}

					case TStamp: {
						int id = toInt(parts[idx++]);
						Tuple2<String, Integer> t2 = splitICMPNumber(parts[idx++], expectedDataLength);
						int sequence = toInt(t2._1);
						int length = t2._2;

						stack.add(new FilterLogICMP(icmpType, id, sequence, length));

						break;
					}

					case Unreach: {
						String tmp = parts[idx++];

						String addressType = null;
						IPAddress address = null;
						String unreachReason = null;
						int length = -1;

						int p0 = tmp.indexOf(' ');
						if (p0 > 0) {
							addressType = tmp.substring(0, p0);

							p0 += 1;
							int p1 = tmp.indexOf(' ', p0);

							if (p1 > 0) {
								address = IPAddress.fromString(tmp.substring(p0, p1).trim());
								p1 += 1;
								Tuple2<String, Integer> t2 = splitICMPNumber(tmp.substring(p1), expectedDataLength);
								unreachReason = t2._1;
								length = t2._2;
							}
						}

						stack.add(new FilterLogICMP(icmpType, addressType, address, unreachReason, length));

						break;
					}

					case UnreachPort: {
						IPAddress address = IPAddress.fromString(parts[idx++]);
						String protocol = parts[idx++];
						Tuple2<String, Integer> t2 = splitICMPNumber(parts[idx++], expectedDataLength);
						int portNumber = toInt(t2._1);
						int length = t2._2;

						stack.add(new FilterLogICMP(icmpType, address, protocol, portNumber, length));

						break;
					}

					case TimeXceed: {
						Tuple2<String, Integer> t2 = splitICMPNumber(parts[idx++], expectedDataLength);

						stack.add(new FilterLogICMP(icmpType, null, null, t2._1, t2._2));

						break;
					}

					case Redirect: {
						String[] tmp = parts[parts.length - 1].split(" ");

						if (tmp.length == 5) {
							IPAddress address = IPAddress.fromString(tmp[1]);
							IPAddress toAddress = IPAddress.fromString(tmp[4]);

							stack.add(new FilterLogICMP(icmpType, address, toAddress));
						} else {
							logRemainder("ICMP: " + tmpICMPType + ": ", idx, parts);
						}

						break;
					}

					default: {
						Tuple2<String, Integer> t2 = splitICMPNumber(parts[parts.length - 1], expectedDataLength);

						stack.add(new FilterLogICMP(icmpType, tmpICMPType, t2._2));
						logRemainder("ICMP: " + tmpICMPType + ": ", idx, parts);

						break;
					}
				}

				break;
			}

			case PROTOCOL_TYPE_TCP: {
				int srcPort = toInt(parts[idx++]);
				int dstPort = toInt(parts[idx++]);
				int dataLength = toInt(parts[idx++]);
				String tcpFlags = parts[idx++];
				int sequenceNumber = toInt(parts[idx++]);
				int tcpAck = toInt(parts[idx++]);
				int window = toInt(parts[idx++]);
				int urg = toInt(parts[idx++]);
				String p[] = parts[idx++].split(";");

				ArrayList<String> tcpOptions = new ArrayList<>();
				for (String str : p)
					tcpOptions.add(str);

				stack.add(new FilterLogTCP(srcPort, dstPort, dataLength, tcpFlags, sequenceNumber, tcpAck, window, urg, tcpOptions));

				break;
			}

			case PROTOCOL_TYPE_UDP: {
				int srcPort = toInt(parts[idx++]);
				int dstPort = toInt(parts[idx++]);
				int dataLength = toInt(parts[idx++]);

				stack.add(new FilterLogUDP(srcPort, dstPort, dataLength));

				break;
			}

			case PROTOCOL_TYPE_OPTIONS:
				/*-
				 * HBH	PADN	RTALERT	0x0000
				 */
				logger.debug(s);
				logRemainder(realInterface + ": " + protocolText, idx, parts);
				break;

			case PROTOCOL_TYPE_GRE:
				/*-
				 * datalength=n
				 */
				logger.debug(s);
				logRemainder(realInterface + ": " + protocolText, idx, parts);
				break;

			case PROTOCOL_TYPE_ESP:
				/*-
				 * datalength=n
				 */
				logger.debug(s);
				logRemainder(realInterface + ": " + protocolText, idx, parts);
				break;

			case PROTOCOL_TYPE_ICMPV6:
				logger.debug(s);
				logRemainder(realInterface + ": " + protocolText, idx, parts);
				break;

			case PROTOCOL_TYPE_OSPF:
				/*-
				 * datalength=48
				 */
				logger.debug(s);
				logRemainder(realInterface + ": " + protocolText, idx, parts);
				break;

			case PROTOCOL_TYPE_IGMP:
				/*-
				 * datalength=n
				 */
				logger.debug(s);
				logRemainder("igmp " + realInterface + ": " + protocolText, idx, parts);
				break;

			default:
				logRemainder(realInterface + ": " + protocolText, idx, parts);
				break;
		}

		return stack;
	}
}
